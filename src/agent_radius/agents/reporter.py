"""Reporter: writes report.md, report.json and report.html from verified findings only."""

from __future__ import annotations

import json
from typing import Any

from agent_radius import __version__
from agent_radius.agents.base import Agent
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import Finding
from agent_radius.agents.ranking import deterministic_order
from agent_radius.llm.advisor import Advisor
from agent_radius.report.render import HEADLINE, render_html, render_markdown
from agent_radius.security.redact import find_secrets, scrub

LIMITATIONS = [
    "AWS only. GCP is a later module.",
    "Single account: cross-account access, assume-role chains and session policies are not modelled.",
    "Conditions are never evaluated; any decisive conditional statement makes a result CONDITIONAL (possible, not certain).",
    "Resource policies are modelled for S3 buckets, KMS keys and AWS Backup vaults only.",
    "Unmodelled resource types (EKS, ECR, Lambda, ...) are checked with an account-wide ARN, not per resource.",
    "Live mode sees only the scanned account, so backup copies in other accounts are visible only through AWS Backup copy jobs or a fixture.",
]


class Reporter(Agent):
    name = "reporter"
    role = "Ranks and explains verified findings and writes the reports."
    tools = frozenset()

    def __init__(self, advisor: Advisor) -> None:
        self.advisor = advisor

    def run(self, board: Blackboard) -> None:
        verified = [f for f in board.verified if f.kind != "guardrail"]
        priority = {arn: i for i, arn in enumerate(board.plan.resource_priority)} if board.plan else None
        order, impacts = self.advisor.rank(verified, priority)
        position = {fid: i for i, fid in enumerate(order)}
        stats = self._stats(board)
        explanations, summary = self.advisor.explain(verified, stats)
        for f in verified:
            f.explanation = explanations.get(f.id, "")
            f.business_impact = impacts.get(f.id, "")
        report = self._build(board, verified, position, stats, summary, priority)
        clean = scrub(report)
        blob = json.dumps(clean, sort_keys=True, default=str)
        hits = find_secrets(blob)
        if hits:  # pragma: no cover - scrub() makes this unreachable unless a pattern is broken
            raise RuntimeError(f"refusing to write a report containing secret-shaped values: {hits}")
        board.report = clean
        if board.out_dir is not None:
            board.out_dir.mkdir(parents=True, exist_ok=True)
            (board.out_dir / "report.json").write_text(json.dumps(clean, indent=2, sort_keys=False, default=str) + "\n", encoding="utf-8")
            (board.out_dir / "report.md").write_text(render_markdown(clean), encoding="utf-8")
            (board.out_dir / "report.html").write_text(render_html(clean), encoding="utf-8")
            board.log(self.name, "note", f"wrote report.md, report.json, report.html to {board.out_dir}")

    def _stats(self, board: Blackboard) -> dict[str, Any]:
        perms = [f for f in board.verified if f.kind == "destructive_permission"]
        eff = [f for f in perms if f.effective and f.outcome == "ALLOW"]
        backups = [f for f in board.verified if f.kind == "backup_survivability"]
        wi = board.verification.get("what_if", {})
        return {
            "effective_destructive": len(eff),
            "irreversible": sum(1 for f in eff if f.irreversibility == 3),
            "conditional": sum(1 for f in perms if f.effective and f.outcome == "CONDITIONAL"),
            "resources_exposed": len({f.resource for f in eff}),
            "at_risk": sum(1 for f in backups if f.verdict == "AT_RISK"),
            "partial": sum(1 for f in backups if f.verdict == "PARTIAL"),
            "survives": sum(1 for f in backups if f.verdict == "SURVIVES"),
            "blocked_by_guardrail": wi.get("blocked") if wi.get("checked") else None,
            "guardrail_checked": wi.get("checked", 0),
            "dropped": len(board.dropped),
        }

    def _build(
        self,
        board: Blackboard,
        verified: list[Finding],
        position: dict[str, int],
        stats: dict[str, Any],
        summary: str,
        priority: dict[str, int] | None = None,
    ) -> dict[str, Any]:
        snap = board.snapshot
        perms = [f for f in verified if f.kind == "destructive_permission"]
        headline = sorted(
            [f for f in perms if f.effective],
            key=lambda f: (-(f.irreversibility or 0), position.get(f.id, 10**6)),
        )
        items = []
        for i, f in enumerate(headline, start=1):
            wi = f.data.get("guardrail_what_if", {})
            items.append(
                {
                    "rank": i,
                    "finding_id": f.id,
                    "action": f.action,
                    "resource": f.resource,
                    "principal": f.principal,
                    "irreversibility": f.irreversibility,
                    "certainty": f.certainty,
                    "outcome": f.outcome,
                    "severity": f.severity,
                    "env": f.env,
                    "consequence": f.consequence,
                    "explanation": f.explanation,
                    "business_impact": f.business_impact,
                    "evidence_ids": [e.id for e in f.evidence if e.kind == "statement"],
                    "guardrail_blocks": ("yes" if wi.get("blocked") else "no") if wi else "n/a",
                }
            )
        backups = []
        for f in deterministic_order([f for f in verified if f.kind == "backup_survivability"], priority):
            a = f.data.get("assessment", {})
            backups.append(
                {
                    "finding_id": f.id,
                    "verdict": f.verdict,
                    "resource": f.resource,
                    "principal": f.principal,
                    "env": f.env,
                    "severity": f.severity,
                    "primary_reason": a.get("primary_reason", ""),
                    "copies": a.get("copies", []),
                    "notes": a.get("notes", []),
                    "verdict_after_guardrail": f.data.get("guardrail_what_if", {}).get("verdict_after"),
                }
            )
        state = [
            {
                "finding_id": f.id,
                "bucket": (f.resource or "").split(":::", 1)[-1],
                "verdict": f.verdict,
                "principal": f.principal,
                "problems": f.data.get("problems", []),
                "checks": f.data.get("checks", {}),
            }
            for f in verified
            if f.kind == "state_bucket"
        ]
        creds = [
            {
                "finding_id": f.id,
                "severity": f.severity,
                "source_type": f.data.get("source_type"),
                "path": f.data.get("path"),
                "detail": f.data.get("detail", ""),
                "key_names": f.data.get("key_names", []),
                "has_static_keys": f.data.get("has_static_keys"),
                "principal": f.principal,
                "mapped_via": f.data.get("mapped_via"),
            }
            for f in verified
            if f.kind == "local_credential"
        ]
        blocked = [
            {"finding_id": f.id, "action": f.action, "resource": f.resource, "principal": f.principal, "notes": f.data.get("notes", [])}
            for f in perms
            if not f.effective
        ]
        g = board.guardrail
        gaps = list(snap.coverage_gaps)
        for f in perms:
            for gap in f.data.get("gaps", []):
                if gap not in gaps:
                    gaps.append(gap)
        ranked = sorted(verified, key=lambda f: position.get(f.id, 10**6))
        return {
            "tool": "agent-radius",
            "version": __version__,
            "headline": HEADLINE,
            "account_id": snap.account_id,
            "regions": list(snap.regions),
            "source": snap.source,
            "agent_principals": list(board.agent_principals),
            "plan": board.plan.to_dict() if board.plan else None,
            "summary": stats,
            "executive_summary": summary,
            "headline_items": items,
            "backups": backups,
            "state_buckets": state,
            "credentials": creds,
            "blocked_by_resource_settings": blocked,
            "findings": [f.to_dict() for f in ranked],
            "guardrail": {
                "files": g.get("files", []),
                "deny_actions": g.get("deny_actions", []),
                "deny_policy": g.get("deny_policy"),
                "principals": g.get("principals", []),
                "what_if": board.verification.get("what_if", {"checked": 0, "blocked": 0}),
            },
            "verification": {k: v for k, v in board.verification.items() if k != "what_if"},
            "dropped_findings": list(board.dropped),
            "coverage_gaps": gaps,
            "trace": [t.to_dict() for t in board.trace],
            "trace_summary": _trace_summary(board),
            "llm": {
                "backend": getattr(self.advisor.backend, "name", "none"),
                "stripped": list(self.advisor.stripped),
                "errors": list(self.advisor.errors),
            },
            "limitations": LIMITATIONS,
        }


def _trace_summary(board: Blackboard) -> list[str]:
    posted: dict[str, int] = {}
    dropped: dict[str, int] = {}
    for t in board.trace:
        if t.event == "post":
            posted[t.agent] = posted.get(t.agent, 0) + 1
    for d in board.dropped:
        dropped[d["posted_by"]] = dropped.get(d["posted_by"], 0) + 1
    lines = []
    for t in board.trace:
        if t.event in ("note", "skip", "llm"):
            lines.append(f"{t.agent}: {t.detail}")
    for agent, n in posted.items():
        lines.append(f"{agent} posted {n} findings; verifier dropped {dropped.get(agent, 0)}")
    return lines
