"""Secret redaction.

Agent Radius is built so that secret values are never stored in the first
place (recon discards them at parse time). This module is the backstop: it
runs over every report before it is written and over every payload before it
could reach an LLM. Patterns target high-confidence credential shapes only.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    (
        "aws_secret_access_key",
        re.compile(
            r"(?i)(?:aws_?secret_?access_?key|secret_?access_?key|aws_?secret)"
            r"[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{40})"
        ),
    ),
    # A bare 40-character base64 run with upper, lower and digit characters
    # and at least one / or +. Hex digests (lowercase hex only) never match.
    (
        "aws_secret_access_key_bare",
        re.compile(
            r"(?<![A-Za-z0-9/+=])(?=[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=]))"
            r"(?=[^\s]*[A-Z])(?=[^\s]*[a-z])(?=[^\s]*[0-9])(?=[^\s]{0,39}[/+])"
            r"[A-Za-z0-9/+]{40}"
        ),
    ),
    ("aws_session_token", re.compile(r"(?i)aws_?session_?token[\"'\s]*[:=][\"'\s]*([A-Za-z0-9/+=]{100,})")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("github_token", re.compile(r"\bgh[psoru]_[A-Za-z0-9]{36,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
]


def find_secrets(text: str) -> list[str]:
    """Return the labels of every secret shape present in ``text``."""
    return [label for label, pattern in SECRET_PATTERNS if pattern.search(text)]


def redact_text(text: str) -> str:
    out = text
    for label, pattern in SECRET_PATTERNS:
        out = pattern.sub(f"{REDACTED}:{label}", out)
    return out


def scrub(value: Any) -> Any:
    """Recursively redact strings inside dicts, lists and tuples."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {scrub(k) if isinstance(k, str) else k: scrub(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    if isinstance(value, tuple):
        return tuple(scrub(v) for v in value)
    return value
