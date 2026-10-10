"""Policy document parsing into normalised statements with evidence ids."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _as_tuple(value: Any) -> tuple[str, ...] | None:
    if value is None:
        return None
    if isinstance(value, str):
        return (value,)
    return tuple(str(v) for v in value)


@dataclass(frozen=True)
class Statement:
    """One statement. ``ref`` is its stable evidence id: ``<policy_ref>#<index>``."""

    ref: str
    policy_ref: str
    policy_type: str  # identity | boundary | scp | resource
    index: int
    sid: str | None
    effect: str  # Allow | Deny
    actions: tuple[str, ...] | None
    not_actions: tuple[str, ...] | None
    resources: tuple[str, ...] | None
    not_resources: tuple[str, ...] | None
    principal: Any
    not_principal: Any
    condition: dict[str, Any] | None

    @property
    def has_condition(self) -> bool:
        return bool(self.condition)


def parse_policy(document: dict[str, Any] | None, policy_ref: str, policy_type: str) -> list[Statement]:
    if not document:
        return []
    raw = document.get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    out: list[Statement] = []
    for index, st in enumerate(raw):
        effect = str(st.get("Effect", "")).capitalize()
        if effect not in ("Allow", "Deny"):
            continue
        actions = _as_tuple(st.get("Action"))
        not_actions = _as_tuple(st.get("NotAction"))
        resources = _as_tuple(st.get("Resource"))
        not_resources = _as_tuple(st.get("NotResource"))
        # SCPs and identity policies may omit Resource; AWS treats a missing
        # Resource in an SCP as "*". Elsewhere it is a malformed statement.
        if resources is None and not_resources is None and policy_type in ("scp", "resource"):
            resources = ("*",)
        out.append(
            Statement(
                ref=f"{policy_ref}#{index}",
                policy_ref=policy_ref,
                policy_type=policy_type,
                index=index,
                sid=st.get("Sid"),
                effect=effect,
                actions=actions,
                not_actions=not_actions,
                resources=resources,
                not_resources=not_resources,
                principal=st.get("Principal"),
                not_principal=st.get("NotPrincipal"),
                condition=st.get("Condition") or None,
            )
        )
    return out
