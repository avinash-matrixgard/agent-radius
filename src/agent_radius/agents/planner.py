"""Planner: decides which specialists run and in what priority order."""

from __future__ import annotations

from agent_radius.agents.assess import STATEFUL_TYPES
from agent_radius.agents.base import Agent
from agent_radius.agents.blackboard import Blackboard, Plan
from agent_radius.llm.advisor import Advisor

SPECIALISTS = ["recon", "permissions", "backup", "guardrail", "verifier", "reporter"]
PRIORITY_TYPES = STATEFUL_TYPES + ("kms_key", "backup_vault", "rds_snapshot", "rds_cluster_snapshot", "ebs_snapshot", "recovery_point")
_ENV_RANK = {"prod": 0, "unknown": 1, "nonprod": 2}
_TYPE_RANK = {t: i for i, t in enumerate(PRIORITY_TYPES)}


class Planner(Agent):
    name = "planner"
    role = "Decides which specialists run and which resources they look at first."
    tools = frozenset({"list_resources"})

    def __init__(self, advisor: Advisor) -> None:
        self.advisor = advisor

    def run(self, board: Blackboard) -> None:
        tb = self.toolbox(board)
        refs = [ref for t in PRIORITY_TYPES for ref in tb.list_resources(t)]
        refs.sort(key=lambda r: (_ENV_RANK.get(r.env, 1), _TYPE_RANK.get(r.resource_type, 99), r.name, r.arn))
        order = [r.arn for r in refs]
        specialists = list(SPECIALISTS)
        stateful = [r for r in refs if r.resource_type in STATEFUL_TYPES]
        if not stateful:
            specialists.remove("backup")
            board.log(self.name, "skip", "backup specialist skipped: the snapshot has no stateful resources")
        context = [
            {"arn": r.arn, "type": r.resource_type, "env": r.env, "name": r.name, "tags": r.tags}
            for r in refs
        ]
        new_order, rationale, changed = self.advisor.reprioritise_plan(order, context)
        if changed:
            board.log(self.name, "llm", "resource priority reordered by the LLM (permutation only)")
        board.plan = Plan(specialists, new_order, rationale, changed)
        prod = sum(1 for r in refs if r.env == "prod")
        board.log(
            self.name,
            "note",
            f"plan: {', '.join(specialists)}; {len(order)} resources, {prod} prod-tagged or prod-named first",
        )
        board.log(self.name, "tool_calls", str(dict(tb.calls)))
