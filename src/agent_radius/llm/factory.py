"""Backend factory."""

from __future__ import annotations

from typing import Any

from agent_radius.llm.anthropic_backend import AnthropicBackend
from agent_radius.llm.base import ModelConfig
from agent_radius.llm.claude_cli_backend import ClaudeCliBackend
from agent_radius.llm.none_backend import NoneBackend

BACKEND_NAMES = ("none", "anthropic", "claude-cli")


def make_backend(name: str, models: ModelConfig | None = None, **kwargs: Any) -> Any:
    if name == "none":
        return NoneBackend()
    if name == "anthropic":
        return AnthropicBackend(models=models, **kwargs)
    if name == "claude-cli":
        return ClaudeCliBackend(models=models, **kwargs)
    raise ValueError(f"unknown LLM backend {name!r}; choose one of {', '.join(BACKEND_NAMES)}")
