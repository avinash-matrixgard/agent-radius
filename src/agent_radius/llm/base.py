"""Backend protocol and model configuration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class LLMError(RuntimeError):
    """Any backend failure. Callers fall back to deterministic output."""


@dataclass(frozen=True)
class ModelConfig:
    """Dual-model design: the larger model plans and writes the executive
    summary, the faster model does per-finding ranking and explanations."""

    planner: str = "claude-opus-5-5"
    summary: str = "claude-opus-5-5"
    worker: str = "claude-sonnet-5-5"

    def for_role(self, role: str) -> str:
        if role == "planner":
            return self.planner
        if role == "summary":
            return self.summary
        return self.worker


class LLMBackend(Protocol):
    name: str

    def complete_json(self, *, role: str, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        """Return parsed JSON. Raise LLMError on any failure."""
        ...
