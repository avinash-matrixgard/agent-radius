"""Guardrail: renders Terraform that would have prevented every finding.
Writes files only; never applies anything."""

from __future__ import annotations

from agent_radius.agents.base import Agent
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import Evidence, Finding
from agent_radius.guardrails.terraform import render_bundle


class Guardrail(Agent):
    name = "guardrail"
    role = "Generates (never applies) Terraform guardrails for what was found."
    tools = frozenset({"catalog_entry", "principal"})

    def run(self, board: Blackboard) -> None:
        tb = self.toolbox(board)
        perms = [f for f in board.findings_of("destructive_permission") if f.outcome in ("ALLOW", "CONDITIONAL")]
        # Only catalogued actions can enter the deny list (anti-hallucination by construction).
        deny_actions = sorted({f.action for f in perms if f.action and tb.catalog_entry(f.action) is not None})
        principals: list[tuple[str, str]] = []
        for arn in sorted({f.principal for f in perms if f.principal}):
            p = tb.principal(arn)
            if p is not None:
                principals.append((p.kind, p.name))
        backups = [f for f in board.findings_of("backup_survivability") if f.verdict in ("AT_RISK", "PARTIAL")]
        at_risk = sorted({f.resource for f in backups if f.resource})
        state = [f for f in board.findings_of("state_bucket") if f.verdict in ("AT_RISK", "PARTIAL")]
        state_buckets = sorted({f.resource.split(":::", 1)[1] for f in state if f.resource})
        bundle = render_bundle(board.snapshot.account_id, deny_actions, principals, at_risk, state_buckets)

        written: list[str] = []
        if board.out_dir is not None:
            gdir = board.out_dir / "guardrails"
            gdir.mkdir(parents=True, exist_ok=True)
            for name, content in bundle.files.items():
                (gdir / name).write_text(content, encoding="utf-8")
                written.append(str(gdir / name))
        board.guardrail = {
            "deny_actions": deny_actions,
            "deny_policy": bundle.deny_policy,
            "boundary_policy": bundle.boundary_policy,
            "principals": [{"kind": k, "name": n} for k, n in principals],
            "at_risk_resources": at_risk,
            "state_buckets": state_buckets,
            "files": sorted(bundle.files),
            "written": written,
            "_bundle": bundle,
        }
        covered = [f.id for f in perms] + [f.id for f in backups] + [f.id for f in state]
        evidence = [Evidence("finding", fid, "covered") for fid in covered]
        evidence += [Evidence("file", f"guardrails/{name}", "generated") for name in sorted(bundle.files)]
        board.post(
            self.name,
            Finding(
                kind="guardrail",
                agent=self.name,
                title=(
                    f"Guardrail Terraform: deny {len(deny_actions)} destructive actions for {len(principals)} principal(s),"
                    f" agent role with boundary, {len(at_risk)} resources to a locked cross-account vault,"
                    f" {len(state_buckets)} state bucket(s) versioned and locked"
                ),
                severity="info",
                evidence=evidence,
                data={"deny_actions": deny_actions, "files": sorted(bundle.files), "covered_findings": covered},
            ),
        )
        board.log(self.name, "note", f"rendered {len(bundle.files)} files; nothing applied")
        board.log(self.name, "tool_calls", str(dict(tb.calls)))
