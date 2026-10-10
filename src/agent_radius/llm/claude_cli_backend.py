"""Claude Code CLI backend: shells out to ``claude -p --model ... --output-format json``.

The prompt goes over stdin, never on the command line. The runner is
injectable so tests use a fake and never spawn the real CLI.
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from typing import Any

from agent_radius.llm.base import LLMError, ModelConfig
from agent_radius.llm.sanitize import extract_json

Runner = Callable[..., Any]


class ClaudeCliBackend:
    name = "claude-cli"

    def __init__(
        self,
        models: ModelConfig | None = None,
        runner: Runner | None = None,
        binary: str = "claude",
        timeout: int = 300,
    ) -> None:
        self.models = models or ModelConfig()
        self._runner = runner or subprocess.run
        self.binary = binary
        self.timeout = timeout

    def complete_json(self, *, role: str, system: str, prompt: str, schema: dict[str, Any]) -> Any:
        cmd = [self.binary, "-p", "--model", self.models.for_role(role), "--output-format", "json"]
        full_prompt = (
            f"{system}\n\nRespond with a single JSON object and nothing else. It must validate against this"
            f" JSON schema:\n{json.dumps(schema, sort_keys=True)}\n\n{prompt}"
        )
        try:
            proc = self._runner(cmd, input=full_prompt, capture_output=True, text=True, timeout=self.timeout, check=False)
        except (OSError, subprocess.SubprocessError) as exc:
            raise LLMError(f"claude CLI failed to run: {type(exc).__name__}") from exc
        if proc.returncode != 0:
            raise LLMError(f"claude CLI exited with {proc.returncode}")
        try:
            envelope = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise LLMError("claude CLI output was not JSON") from exc
        if isinstance(envelope, dict) and envelope.get("is_error"):
            raise LLMError("claude CLI reported an error")
        result = envelope.get("result") if isinstance(envelope, dict) and "result" in envelope else envelope
        if isinstance(result, str):
            try:
                return extract_json(result)
            except json.JSONDecodeError as exc:
                raise LLMError("model reply was not JSON") from exc
        return result
