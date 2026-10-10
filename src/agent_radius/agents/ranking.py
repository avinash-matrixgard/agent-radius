"""Deterministic ordering shared by the Reporter and the LLM advisor."""

from __future__ import annotations

from agent_radius.agents.findings import Finding, severity_rank
from agent_radius.catalog import by_action

KIND_ORDER = {
    "destructive_permission": 0,
    "backup_survivability": 1,
    "state_bucket": 2,
    "local_credential": 3,
    "guardrail": 4,
}
CATEGORY_ORDER = {
    "data_loss": 0,
    "backup_loss": 1,
    "escalation": 2,
    "protection_weakening": 3,
    "audit_blinding": 4,
    "disruption": 5,
}


def _priority(f: Finding, priority: dict[str, int] | None) -> int:
    if not priority or not f.resource:
        return 10**6
    if f.resource in priority:
        return priority[f.resource]
    return priority.get(f.resource.removesuffix("/*"), 10**6)


def default_key(f: Finding, priority: dict[str, int] | None = None) -> tuple:
    entry = by_action(f.action) if f.action else None
    return (
        not f.effective,
        -(f.irreversibility or 0),
        bool(f.data.get("latent")),
        -severity_rank(f.severity),
        f.env != "prod",
        f.certainty != "certain",
        KIND_ORDER.get(f.kind, 9),
        CATEGORY_ORDER.get(entry.category, 9) if entry else 9,
        _priority(f, priority),
        f.action or "",
        f.resource or "",
        f.id,
    )


def deterministic_order(findings: list[Finding], priority: dict[str, int] | None = None) -> list[Finding]:
    return sorted(findings, key=lambda f: default_key(f, priority))


def short_arn(arn: str | None) -> str:
    if not arn:
        return "-"
    if arn.startswith("arn:aws:iam::"):
        return arn.split(":", 5)[-1]
    if arn.startswith("arn:aws:s3:::"):
        return "s3://" + arn[len("arn:aws:s3:::") :]
    parts = arn.split(":", 5)
    return parts[-1] if len(parts) == 6 else arn
