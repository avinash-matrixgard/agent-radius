"""Agent base class."""

from __future__ import annotations

from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.tools import Toolbox


class Agent:
    name: str = "agent"
    role: str = ""
    tools: frozenset[str] = frozenset()

    def toolbox(self, board: Blackboard) -> Toolbox:
        return Toolbox(board.snapshot, board.evaluator, self.tools)

    def run(self, board: Blackboard) -> None:  # pragma: no cover - interface
        raise NotImplementedError

    def execute(self, board: Blackboard) -> None:
        board.log(self.name, "start", self.role)
        self.run(board)
        board.log(self.name, "finish", "")
