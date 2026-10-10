"""The shared blackboard every agent reads from and posts to."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_radius.agents.findings import Finding
from agent_radius.iam.evaluator import Evaluator
from agent_radius.snapshot.model import LocalCredential, Snapshot


@dataclass
class TraceEvent:
    seq: int
    agent: str
    event: str  # start | finish | post | drop | note | llm | skip | tool_calls
    detail: str = ""
    finding_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "agent": self.agent,
            "event": self.event,
            "detail": self.detail,
            "finding_id": self.finding_id,
        }


@dataclass
class Plan:
    specialists: list[str]
    resource_priority: list[str]
    rationale: str
    llm_adjusted: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "specialists": list(self.specialists),
            "resource_priority": list(self.resource_priority),
            "rationale": self.rationale,
            "llm_adjusted": self.llm_adjusted,
        }


@dataclass
class Blackboard:
    snapshot: Snapshot
    evaluator: Evaluator
    out_dir: Path | None = None
    plan: Plan | None = None
    agent_principals: list[str] = field(default_factory=list)
    credentials: list[LocalCredential] = field(default_factory=list)
    findings: dict[str, Finding] = field(default_factory=dict)
    verified: list[Finding] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)
    trace: list[TraceEvent] = field(default_factory=list)
    guardrail: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] = field(default_factory=dict)
    llm: dict[str, Any] = field(default_factory=lambda: {"backend": "none", "stripped": [], "errors": []})
    report: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def log(self, agent: str, event: str, detail: str = "", finding_id: str | None = None) -> None:
        with self._lock:
            self.trace.append(TraceEvent(len(self.trace) + 1, agent, event, detail, finding_id))

    def post(self, agent: str, finding: Finding) -> None:
        if not finding.evidence:
            raise ValueError(f"{agent} tried to post finding {finding.id} without evidence")
        with self._lock:
            if finding.id in self.findings:
                return
            self.findings[finding.id] = finding
            self.trace.append(TraceEvent(len(self.trace) + 1, agent, "post", finding.title, finding.id))

    def drop(self, by: str, finding: Finding, reason: str) -> None:
        with self._lock:
            self.dropped.append(
                {"finding_id": finding.id, "posted_by": finding.agent, "dropped_by": by, "reason": reason, "title": finding.title}
            )
            self.trace.append(TraceEvent(len(self.trace) + 1, by, "drop", reason, finding.id))

    def findings_of(self, kind: str, verified_only: bool = False) -> list[Finding]:
        pool = self.verified if verified_only else list(self.findings.values())
        return [f for f in pool if f.kind == kind]
