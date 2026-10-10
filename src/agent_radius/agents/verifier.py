"""Verifier: the gate between what the specialists claim and what is reported.

1. Anti-hallucination: drops any finding naming a principal, resource,
   action, statement, credential or file that is absent from the snapshot,
   the catalog or this run.
2. Reproduction: re-runs the evaluator (and the survivability assessment)
   for every finding and drops anything whose outcome, verdict or cited
   statements do not reproduce.
3. What-if: attaches the generated deny policy to each agent principal in a
   copy of the snapshot and records which findings it would block.
4. Terraform: structural HCL check always; ``terraform validate`` only when
   Terraform is installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from agent_radius.agents.assess import STATEFUL_TYPES, assess_survivability, effective_permission
from agent_radius.agents.base import Agent
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import Finding
from agent_radius.agents.tools import ALL_TOOLS, Toolbox
from agent_radius.catalog import CATALOG, account_wide_arn, by_action
from agent_radius.guardrails.hcl import check_hcl
from agent_radius.iam.evaluator import Evaluator
from agent_radius.iam.policy import parse_policy
from agent_radius.security.redact import find_secrets
from agent_radius.snapshot.model import Snapshot

WHATIF_POLICY_NAME = "agent-radius-deny-destructive"


def all_statement_refs(evaluator: Evaluator) -> set[str]:
    snap = evaluator.snapshot
    refs: set[str] = set()
    for p in snap.iam.all_principals():
        stmts, _ = evaluator.identity_statements(p)
        refs |= {s.ref for s in stmts}
        boundary, _ = evaluator.boundary_statements(p)
        refs |= {s.ref for s in boundary or []}
    for level in (evaluator.scp_levels() or {}).values():
        refs |= {s.ref for s in level}
    for b in snap.resources.s3_buckets:
        refs |= {s.ref for s in parse_policy(b.policy, f"resource:s3:{b.arn}", "resource")}
    for k in snap.resources.kms_keys:
        refs |= {s.ref for s in parse_policy(k.policy, f"resource:kms:{k.arn}", "resource")}
    for v in snap.resources.backup_vaults:
        refs |= {s.ref for s in parse_policy(v.access_policy, f"resource:backup:{v.arn}", "resource")}
    return refs


def known_resource_arns(snap: Snapshot) -> set[str]:
    arns = set(snap.resource_index())
    for b in snap.resources.s3_buckets:
        for rule in b.replication:
            arns.add(rule.destination_bucket_arn)
    for entry in CATALOG:
        if not entry.modelled:
            arns.add(account_wide_arn(entry, snap.account_id, snap.region))
    return arns


class Verifier(Agent):
    name = "verifier"
    role = "Re-derives every finding from the snapshot and drops anything that does not reproduce."
    tools = frozenset({"evaluate", "get_resource", "catalog_entry", "account_wide_arn", "principal", "list_resources"})

    def __init__(self, terraform_bin: str | None = "auto", runner: Any = None) -> None:
        self.terraform_bin = terraform_bin
        self._runner = runner or subprocess.run

    # ---- checks ------------------------------------------------------------

    def _check(self, f: Finding, board: Blackboard, tb: Toolbox, ctx: dict[str, Any]) -> str | None:
        snap = board.snapshot
        if not f.evidence:
            return "no evidence cited"
        for e in f.evidence:
            if e.kind == "statement" and e.id not in ctx["statements"]:
                return f"cites statement {e.id}, which does not exist in the snapshot"
            if e.kind == "resource" and e.id not in ctx["resources"]:
                return f"cites resource {e.id}, which is not in the snapshot"
            if e.kind == "fixture" and e.id != snap.source:
                return f"cites snapshot source {e.id}, which is not this run's source"
            if e.kind == "credential" and e.id not in ctx["credentials"]:
                return f"cites credential {e.id}, which recon did not find"
            if e.kind == "finding" and e.id not in board.findings:
                return f"cites finding {e.id}, which was never posted"
            if e.kind == "file" and e.id.split("/", 1)[-1] not in ctx["files"]:
                return f"cites file {e.id}, which the guardrail agent did not generate"
        if f.principal is not None and snap.iam.principal(f.principal) is None:
            return f"names principal {f.principal}, which is not in the snapshot"
        if f.action is not None and by_action(f.action) is None:
            return f"names action {f.action}, which is not in the catalog"
        if f.resource is not None and f.resource not in ctx["resources"]:
            return f"names resource {f.resource}, which is not in the snapshot"
        if find_secrets(json.dumps(f.to_dict(), default=str)):
            return "contains a secret-shaped value"

        if f.kind == "destructive_permission":
            return self._reproduce_permission(f, tb)
        if f.kind in ("backup_survivability", "state_bucket"):
            return self._reproduce_backup(f, tb)
        if f.kind == "local_credential":
            if f.data.get("credential_id") not in ctx["credentials"]:
                return "credential record not found"
            return None
        if f.kind == "guardrail":
            bad = [a for a in f.data.get("deny_actions", []) if by_action(a) is None]
            if bad:
                return f"deny list contains non-catalog actions {bad}"
            if ctx["hcl_problems"]:
                return "generated Terraform failed the structural HCL check"
            return None
        return f"unknown finding kind {f.kind}"

    def _reproduce_permission(self, f: Finding, tb: Toolbox) -> str | None:
        assert f.principal and f.action and f.resource
        entry = by_action(f.action)
        assert entry is not None
        ref = tb.get_resource(f.resource)
        if ref is None:
            if entry.modelled:
                return f"{f.action} targets a modelled resource type but {f.resource} is not in the snapshot"
            if f.resource != tb.account_wide_arn(entry):
                return f"{f.resource} is not the account-wide ARN for {f.action}"
        elif ref.resource_type != entry.resource_type:
            return f"{f.action} acts on {entry.resource_type}, but {f.resource} is a {ref.resource_type}"
        eff = effective_permission(tb, f.principal, f.action, ref, f.resource)
        if eff.decision.outcome.value != f.outcome:
            return f"does not reproduce: evaluator says {eff.decision.outcome.value}, finding says {f.outcome}"
        if eff.effective != f.effective:
            return "does not reproduce: resource protections differ"
        allowed = set(eff.decision.evidence_ids) | {m.ref for c in eff.companions for m in c.matched}
        cited = {e.id for e in f.evidence if e.kind == "statement"}
        extra = cited - allowed
        if extra:
            return f"cites statements the evaluator did not match: {sorted(extra)}"
        if not cited & set(eff.decision.evidence_ids):
            return "cites none of the statements that decide this request"
        return None

    def _reproduce_backup(self, f: Finding, tb: Toolbox) -> str | None:
        assert f.principal and f.resource
        ref = tb.get_resource(f.resource)
        if ref is None or ref.resource_type not in STATEFUL_TYPES:
            return f"{f.resource} is not a stateful resource in the snapshot"
        a = assess_survivability(tb, f.principal, ref)
        if a.verdict != f.verdict:
            return f"does not reproduce: assessment says {a.verdict}, finding says {f.verdict}"
        allowed = {m.ref for d in a.decisions for m in d.matched}
        if f.kind == "state_bucket":
            b = ref.obj
            for act, arn in (
                ("s3:DeleteObject", b.objects_arn),
                ("s3:DeleteObjectVersion", b.objects_arn),
                ("s3:PutBucketVersioning", b.arn),
                ("s3:PutLifecycleConfiguration", b.arn),
            ):
                allowed |= set(tb.evaluate(f.principal, act, arn).evidence_ids)
        cited = {e.id for e in f.evidence if e.kind == "statement"}
        extra = cited - allowed
        if extra:
            return f"cites statements the assessment did not match: {sorted(extra)}"
        return None

    # ---- terraform -----------------------------------------------------------

    def _hcl_check(self, board: Blackboard) -> dict[str, list[str]]:
        bundle = board.guardrail.get("_bundle")
        if bundle is None:
            return {}
        problems: dict[str, list[str]] = {}
        for name, content in bundle.files.items():
            if not name.endswith(".tf"):
                continue
            issues = check_hcl(content, bundle.policies_by_file.get(name))
            if issues:
                problems[name] = issues
        return problems

    def _terraform_validate(self, board: Blackboard) -> dict[str, Any]:
        binary = shutil.which("terraform") if self.terraform_bin == "auto" else self.terraform_bin
        if not binary:
            return {"status": "skipped", "reason": "terraform not installed"}
        if board.out_dir is None or not board.guardrail.get("written"):
            return {"status": "skipped", "reason": "no guardrail files were written to disk"}
        gdir = str(board.out_dir / "guardrails")
        try:
            init = self._runner(
                [binary, f"-chdir={gdir}", "init", "-backend=false", "-input=false", "-no-color"],
                capture_output=True, text=True, timeout=600, check=False,
            )
            if init.returncode != 0:
                return {"status": "error", "reason": "terraform init failed", "output": (init.stderr or "")[-2000:]}
            val = self._runner(
                [binary, f"-chdir={gdir}", "validate", "-json", "-no-color"],
                capture_output=True, text=True, timeout=300, check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return {"status": "error", "reason": f"terraform failed to run: {type(exc).__name__}"}
        try:
            result = json.loads(val.stdout or "{}")
        except json.JSONDecodeError:
            result = {}
        return {
            "status": "passed" if result.get("valid") else "failed",
            "error_count": result.get("error_count"),
            "warning_count": result.get("warning_count"),
            "diagnostics": [d.get("summary") for d in result.get("diagnostics", [])][:20],
        }

    # ---- what-if -----------------------------------------------------------

    def _what_if(self, board: Blackboard) -> dict[str, Any]:
        deny = board.guardrail.get("deny_policy")
        perms = [f for f in board.verified if f.kind == "destructive_permission"]
        if not deny or not perms:
            return {"checked": 0, "blocked": 0, "not_blocked": []}
        snap = board.snapshot
        for principal in sorted({f.principal for f in perms if f.principal}):
            snap = snap.with_inline_policy(principal, WHATIF_POLICY_NAME, deny)
        ev = Evaluator(snap)
        tb = Toolbox(snap, ev, ALL_TOOLS)
        blocked = 0
        not_blocked = []
        for f in perms:
            d = ev.evaluate(f.principal, f.action, f.resource)
            is_blocked = not d.outcome.permits
            blocked += is_blocked
            f.data["guardrail_what_if"] = {"blocked": is_blocked, "outcome_after": d.outcome.value}
            if not is_blocked:
                not_blocked.append(f.id)
        verdicts_after: dict[str, int] = {}
        for f in board.verified:
            if f.kind not in ("backup_survivability", "state_bucket"):
                continue
            ref = snap.resource(f.resource)
            if ref is None or f.principal not in snap.principal_arns():
                continue
            after = assess_survivability(tb, f.principal, ref).verdict
            f.data["guardrail_what_if"] = {"verdict_after": after}
            verdicts_after[after] = verdicts_after.get(after, 0) + 1
        return {"checked": len(perms), "blocked": blocked, "not_blocked": not_blocked, "backup_verdicts_after": verdicts_after}

    # ---- run -----------------------------------------------------------------

    def run(self, board: Blackboard) -> None:
        tb = self.toolbox(board)
        hcl_problems = self._hcl_check(board)
        ctx = {
            "statements": all_statement_refs(board.evaluator),
            "resources": known_resource_arns(board.snapshot),
            "credentials": {c.id for c in board.credentials},
            "files": set(board.guardrail.get("files", [])),
            "hcl_problems": hcl_problems,
        }
        verified: list[Finding] = []
        for f in sorted(board.findings.values(), key=lambda x: x.id):
            reason = self._check(f, board, tb, ctx)
            if reason:
                board.drop(self.name, f, reason)
            else:
                verified.append(f)
        board.verified = verified
        what_if = self._what_if(board)
        terraform = self._terraform_validate(board)
        board.verification = {
            "posted": len(board.findings),
            "verified": len(verified),
            "dropped": len(board.dropped),
            "what_if": what_if,
            "hcl_check": {"status": "failed" if hcl_problems else "passed", "problems": hcl_problems},
            "terraform_validate": terraform,
        }
        board.log(
            self.name,
            "note",
            f"verified {len(verified)} of {len(board.findings)} findings; what-if: deny policy blocks"
            f" {what_if['blocked']} of {what_if['checked']}; terraform validate: {terraform['status']}"
            + (f" ({terraform['reason']})" if terraform.get("reason") else ""),
        )
        board.log(self.name, "tool_calls", str(dict(tb.calls)))
