"""The default backend: no model at all. The Advisor produces deterministic
output when it sees this backend, so ``complete_json`` is never called."""

from __future__ import annotations

from typing import Any

from agent_radius.llm.base import LLMError


class NoneBackend:
    name = "none"

    def complete_json(self, *, role: str, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        raise LLMError("the none backend does not call a model")
