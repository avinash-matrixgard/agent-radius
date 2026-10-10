"""Anthropic SDK backend.

Uses structured outputs (``output_config.format`` with a JSON schema) and
opts into the server-side refusal fallback. A refusal or any API error
raises LLMError and the Advisor falls back to deterministic output. The
client is injectable so tests use a fake and never touch the network.
"""

from __future__ import annotations

import json
from typing import Any

from agent_radius.llm.base import LLMError, ModelConfig

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicBackend:
    name = "anthropic"

    def __init__(
        self,
        models: ModelConfig | None = None,
        client: Any = None,
        max_tokens: int = 16000,
        effort: str = "medium",
        use_fallbacks: bool = True,
    ) -> None:
        self.models = models or ModelConfig()
        self._client = client
        self.max_tokens = max_tokens
        self.effort = effort
        self.use_fallbacks = use_fallbacks

    def _get_client(self) -> Any:
        if self._client is None:
            try:
                import anthropic  # noqa: PLC0415 - optional dependency
            except ImportError as exc:  # pragma: no cover - depends on install
                raise LLMError("the anthropic backend needs `pip install agent-radius[anthropic]`") from exc
            self._client = anthropic.Anthropic()
        return self._client

    def complete_json(self, *, role: str, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        client = self._get_client()
        kwargs: dict[str, Any] = {
            "model": self.models.for_role(role),
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": prompt}],
            "output_config": {"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        }
        try:
            if self.use_fallbacks:
                response = client.beta.messages.create(betas=[FALLBACK_BETA], fallbacks="default", **kwargs)
            else:
                response = client.messages.create(**kwargs)
        except Exception as exc:  # noqa: BLE001 - every SDK error becomes LLMError
            raise LLMError(f"anthropic call failed: {type(exc).__name__}") from exc
        if getattr(response, "stop_reason", None) == "refusal":
            raise LLMError("the model declined the request")
        text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), None)
        if text is None:
            raise LLMError("no text block in the response")
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError("response was not valid JSON") from exc
