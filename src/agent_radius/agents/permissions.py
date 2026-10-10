"""Permissions: evaluates every catalogued destructive action for every
agent principal against every matching resource in the snapshot."""

from __future__ import annotations

from agent_radius.agents.assess import effective_permission
from agent_radius.agents.base import Agent
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import Evidence, Finding, score_severity
from agent_radius.agents.ranking import short_arn
from agent_radius.iam.evaluator import Outcome


class Permissions(Agent):
    name = "permissions"
    role = "Evaluates every catalogued destructive action for each agent principal."
    tools = frozenset({"evaluate", "list_resources", "catalog", "account_wide_arn", "catalog_entry"})

    def run(self, board: Blackboard) -> None:
        tb = self.toolbox(board)
        snap = board.snapshot
        priority = {arn: i for i, arn in enumerate(board.plan.resource_priority if board.plan else [])}
        checked = 0
        for principal in board.agent_principals:
            for entry in tb.catalog():
                if entry.modelled:
                    targets = sorted(tb.list_resources(entry.resource_type), key=lambda r: (priority.get(r.arn, 10**6), r.arn))
                    pairs = [(r, r.arn) for r in targets]
                else:
                    pairs = [(None, tb.account_wide_arn(entry))]
                for ref, arn in pairs:
                    checked += 1
                    eff = effective_permission(tb, principal, entry.action, ref, arn)
                    d = eff.decision
                    if not d.outcome.permits:
                        continue
                    certainty = "certain" if d.outcome == Outcome.ALLOW else "possible"
                    env = ref.env if ref is not None else "unknown"
                    notes = list(eff.notes) + list(d.notes)
                    if ref is not None and ref.resource_type in ("iam_role", "iam_user") and arn == principal:
                        notes.append("this is the agent's own identity")
                    latent = False
                    if ref is not None and ref.resource_type == "dynamodb_backup" and arn.endswith("/backup/*"):
                        table = ref.obj
                        if not table.backups and not table.pitr_enabled:
                            latent = True
                            notes.append("no backups exist for this table today; the grant covers any future backup")
                    conditions = [m.why_conditional for m in d.matched if m.conditional and m.why_conditional]
                    evidence = [Evidence("statement", m.ref, f"{m.effect} {m.sid or ''}".strip()) for m in d.matched]
                    for comp in eff.companions:
                        evidence += [Evidence("statement", m.ref, f"companion {comp.action}") for m in comp.matched]
                    evidence.append(Evidence("resource", arn, "resource" if ref is not None else "account-wide"))
                    evidence.append(Evidence("fixture", snap.source, "snapshot"))
                    severity = score_severity(eff.irreversibility, certainty, env, eff.effective, entry.category)
                    if latent and severity in ("critical", "high"):
                        severity = "medium"
                    title = f"{short_arn(principal)} can call {entry.action} on {short_arn(arn)}"
                    if certainty == "possible":
                        title += " (possible, conditional)"
                    if not eff.effective:
                        title += " (blocked by a resource setting)"
                    board.post(
                        self.name,
                        Finding(
                            kind="destructive_permission",
                            agent=self.name,
                            title=title,
                            severity=severity,
                            principal=principal,
                            action=entry.action,
                            resource=arn,
                            outcome=d.outcome.value,
                            certainty=certainty,
                            irreversibility=eff.irreversibility,
                            effective=eff.effective,
                            env=env,
                            consequence=entry.consequence,
                            evidence=_dedupe(evidence),
                            data={
                                "resource_type": entry.resource_type if ref is None else ref.resource_type,
                                "scope": "resource" if ref is not None else "account-wide",
                                "category": entry.category,
                                "notes": notes,
                                "conditions": conditions,
                                "gaps": list(d.gaps),
                                "companions": [c.to_dict() for c in eff.companions],
                                "latent": latent,
                            },
                        ),
                    )
        board.log(self.name, "note", f"evaluated {checked} (principal, action, resource) combinations")
        board.log(self.name, "tool_calls", str(dict(tb.calls)))


def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
    seen: set[tuple[str, str]] = set()
    out = []
    for e in evidence:
        key = (e.kind, e.id)
        if key in seen:
            continue
        seen.add(key)
        out.append(e)
    return out
