"""Structured findings. Every finding must cite evidence ids."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITIES = ("info", "low", "medium", "high", "critical")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

KIND_PREFIX = {
    "destructive_permission": "perm",
    "backup_survivability": "bkp",
    "state_bucket": "tfst",
    "local_credential": "cred",
    "guardrail": "grd",
}


def severity_rank(severity: str) -> int:
    return _SEV_RANK.get(severity, 0)


def severity_at_least(severity: str, floor: str) -> bool:
    return severity_rank(severity) >= severity_rank(floor)


def score_severity(irreversibility: int, certainty: str, env: str, effective: bool, category: str) -> str:
    """Deterministic severity. Documented in docs/DESIGN.md."""
    if not effective:
        return "low"
    score = irreversibility
    if env == "prod":
        score += 1
    if category == "escalation":
        score = max(score, 3)
    if certainty == "possible":
        score -= 1
    if score >= 4:
        return "critical"
    if score == 3:
        return "high"
    if score == 2:
        return "medium"
    return "low"


@dataclass
class Evidence:
    kind: str  # statement | resource | fixture | credential | decision | finding | file
    id: str
    detail: str = ""


@dataclass
class Finding:
    kind: str
    agent: str
    title: str
    severity: str
    principal: str | None = None
    action: str | None = None
    resource: str | None = None
    outcome: str | None = None
    verdict: str | None = None
    certainty: str = "certain"  # certain | possible
    irreversibility: int | None = None
    effective: bool = True
    env: str = "unknown"
    consequence: str = ""
    evidence: list[Evidence] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    business_impact: str = ""
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            self.id = finding_id(self.kind, self.principal, self.action, self.resource, self.data.get("id_salt"))

    @property
    def evidence_ids(self) -> list[str]:
        return [e.id for e in self.evidence]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        data = dict(data)
        data["evidence"] = [Evidence(**e) for e in data.get("evidence", [])]
        return cls(**data)


def finding_id(kind: str, principal: str | None, action: str | None, resource: str | None, salt: Any = None) -> str:
    raw = "|".join([kind, principal or "", action or "", resource or "", str(salt or "")])
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
    return f"{KIND_PREFIX.get(kind, 'fnd')}-{digest}"
