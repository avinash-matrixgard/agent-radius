"""Backup: per stateful resource, can the agent destroy it AND every copy?"""

from __future__ import annotations

from agent_radius.agents.assess import (
    LOST,
    STATEFUL_TYPES,
    Assessment,
    assess_survivability,
    is_state_bucket,
    perm,
)
from agent_radius.agents.base import Agent
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import Evidence, Finding
from agent_radius.agents.ranking import short_arn
from agent_radius.agents.tools import Toolbox
from agent_radius.snapshot.model import ResourceRef, S3Bucket

_SEVERITY = {
    ("AT_RISK", "prod"): "critical",
    ("AT_RISK", "unknown"): "high",
    ("AT_RISK", "nonprod"): "high",
    ("PARTIAL", "prod"): "high",
    ("PARTIAL", "unknown"): "medium",
    ("PARTIAL", "nonprod"): "medium",
}


def backup_severity(verdict: str, env: str) -> str:
    return _SEVERITY.get((verdict, env), "info")


def assessment_evidence(a: Assessment, source: str) -> list[Evidence]:
    ev = [Evidence("resource", a.resource, "assessed resource")]
    for c in a.copies:
        if c.arn:
            ev.append(Evidence("resource", c.arn, f"copy: {c.kind}"))
    seen = set()
    for d in a.decisions:
        if not d.outcome.permits:
            continue
        for m in d.matched:
            if m.ref not in seen:
                seen.add(m.ref)
                ev.append(Evidence("statement", m.ref, f"{d.action} {d.outcome.value}"))
    ev.append(Evidence("fixture", source, "snapshot"))
    return ev


def stateful_targets(tb: Toolbox, priority: dict[str, int]) -> list[ResourceRef]:
    snap = tb.snapshot
    cluster_ids = {c.identifier for c in snap.resources.rds_clusters}
    refs: list[ResourceRef] = []
    for t in STATEFUL_TYPES:
        for ref in tb.list_resources(t):
            # Aurora instances hold no data of their own; the cluster is assessed.
            if t == "rds_instance" and getattr(ref.obj, "cluster_identifier", None) in cluster_ids:
                continue
            refs.append(ref)
    refs.sort(key=lambda r: (priority.get(r.arn, 10**6), r.arn))
    return refs


class Backup(Agent):
    name = "backup"
    role = "Decides whether each stateful resource and its backups survive the agent."
    tools = frozenset({"evaluate", "list_resources", "account_wide_arn", "get_resource"})

    def run(self, board: Blackboard) -> None:
        tb = self.toolbox(board)
        snap = board.snapshot
        priority = {arn: i for i, arn in enumerate(board.plan.resource_priority if board.plan else [])}
        targets = stateful_targets(tb, priority)
        for principal in board.agent_principals:
            for ref in targets:
                a = assess_survivability(tb, principal, ref)
                certainty = "certain" if a.verdict != "PARTIAL" else "possible"
                irr = {"AT_RISK": 3, "PARTIAL": 2}.get(a.verdict)
                title = f"{a.verdict}: {short_arn(ref.arn)} vs {short_arn(principal)}"
                board.post(
                    self.name,
                    Finding(
                        kind="backup_survivability",
                        agent=self.name,
                        title=title,
                        severity=backup_severity(a.verdict, ref.env),
                        principal=principal,
                        resource=ref.arn,
                        verdict=a.verdict,
                        certainty=certainty,
                        irreversibility=irr,
                        env=ref.env,
                        evidence=assessment_evidence(a, snap.source),
                        data={"assessment": a.to_dict(), "notes": list(a.notes), "resource_type": ref.resource_type},
                    ),
                )
                if isinstance(ref.obj, S3Bucket) and is_state_bucket(ref.obj):
                    self._state_bucket(board, tb, principal, ref, a)
        board.log(self.name, "tool_calls", str(dict(tb.calls)))

    def _state_bucket(self, board: Blackboard, tb: Toolbox, principal: str, ref: ResourceRef, a: Assessment) -> None:
        b: S3Bucket = ref.obj
        checks = {
            "delete_objects": tb.evaluate(principal, "s3:DeleteObject", b.objects_arn),
            "delete_object_versions": tb.evaluate(principal, "s3:DeleteObjectVersion", b.objects_arn),
            "suspend_versioning": tb.evaluate(principal, "s3:PutBucketVersioning", b.arn),
            "lifecycle_expire": tb.evaluate(principal, "s3:PutLifecycleConfiguration", b.arn),
        }
        problems = []
        if b.versioning != "Enabled":
            problems.append(f"versioning is {b.versioning.lower()}")
        if not b.object_lock.enabled:
            problems.append("no Object Lock")
        can = [k.replace("_", " ") for k, d in checks.items() if perm(d) == LOST]
        if can:
            problems.append("agent can " + ", ".join(can))
        severity = {"AT_RISK": "critical", "PARTIAL": "high"}.get(a.verdict, "info")
        ev = assessment_evidence(a, board.snapshot.source)
        for d in checks.values():
            ev += [Evidence("statement", m.ref, f"{d.action} {d.outcome.value}") for m in d.matched if d.outcome.permits]
        seen = set()
        ev = [e for e in ev if not ((e.kind, e.id) in seen or seen.add((e.kind, e.id)))]
        board.post(
            self.name,
            Finding(
                kind="state_bucket",
                agent=self.name,
                title=f"Terraform state bucket {b.name}: {a.verdict}" + (f" ({'; '.join(problems)})" if problems else ""),
                severity=severity,
                principal=principal,
                resource=b.arn,
                verdict=a.verdict,
                certainty="certain" if a.verdict != "PARTIAL" else "possible",
                irreversibility={"AT_RISK": 3, "PARTIAL": 2}.get(a.verdict),
                env=ref.env,
                consequence="Losing Terraform state orphans every resource it tracks; the next apply can try to recreate or destroy them.",
                evidence=ev,
                data={
                    "versioning": b.versioning,
                    "object_lock": b.object_lock.mode if b.object_lock.enabled else None,
                    "mfa_delete": b.mfa_delete,
                    "checks": {k: d.outcome.value for k, d in checks.items()},
                    "problems": problems,
                    "assessment": a.to_dict(),
                    "notes": list(a.notes),
                    "resource_type": "s3_bucket",
                },
            ),
        )
