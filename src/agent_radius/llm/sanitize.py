"""Input and output hygiene for anything that touches an LLM.

Inputs: only verified-finding summaries are sent. The payload is scrubbed
and then checked: if any secret-shaped string survives, nothing is sent.

Outputs: every ARN or IAM action an LLM mentions must already appear in the
verified findings (or, for planning, in the snapshot). Anything else is
replaced with a marker and logged.
"""

from __future__ import annotations

import json
import re
from typing import Any

from agent_radius.catalog import CATALOG
from agent_radius.security.redact import find_secrets, scrub

ARN_RE = re.compile(r"arn:aws[a-z-]*:[A-Za-z0-9-]*:[a-z0-9-]*:[0-9]{0,12}:[^\s\"'<>(),;\]\[`]+")
ACTION_RE = re.compile(r"\b([a-z][a-z0-9-]{1,40}):([A-Z][A-Za-z0-9]*\*?|\*)")

KNOWN_SERVICES = {c.service for c in CATALOG} | {
    "sts", "ec2", "s3", "iam", "kms", "rds", "dynamodb", "backup", "lambda", "logs", "cloudtrail",
    "organizations", "eks", "ecr", "ecs", "sns", "sqs", "ssm", "secretsmanager", "route53",
    "cloudformation", "cloudwatch", "athena", "glue", "redshift", "es", "elasticache",
    "elasticfilesystem", "guardduty", "config", "sso", "apigateway", "states", "kinesis",
}

UNVERIFIED = "[removed: not in verified findings]"


class UnsafePayload(RuntimeError):
    pass


def safe_payload(payload: Any) -> str:
    """Serialise a payload for an LLM, refusing if a secret shape remains."""
    text = json.dumps(scrub(payload), sort_keys=True, default=str)
    hits = find_secrets(text)
    if hits:
        raise UnsafePayload(f"refusing to send payload containing secret-shaped values: {hits}")
    return text


def strip_unverified(text: str, allowed_arns: set[str], allowed_actions: set[str]) -> tuple[str, list[str]]:
    stripped: list[str] = []
    allowed_lower = {a.lower() for a in allowed_actions}

    def arn_sub(m: re.Match[str]) -> str:
        arn = m.group(0).rstrip(".")
        tail = m.group(0)[len(arn) :]
        if arn in allowed_arns:
            return m.group(0)
        stripped.append(arn)
        return UNVERIFIED + tail

    out = ARN_RE.sub(arn_sub, text)

    def action_sub(m: re.Match[str]) -> str:
        service, name = m.group(1), m.group(2)
        if service not in KNOWN_SERVICES:
            return m.group(0)
        action = f"{service}:{name}"
        if action.lower() in allowed_lower:
            return m.group(0)
        stripped.append(action)
        return UNVERIFIED

    out = ACTION_RE.sub(action_sub, out)
    return out, stripped


def extract_json(text: str) -> Any:
    """Parse JSON from a model reply, tolerating code fences and prose around it."""
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text)
        text = re.sub(r"\n?```\s*$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            return json.loads(text[start : end + 1])
        raise
