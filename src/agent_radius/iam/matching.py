"""Wildcard matching for IAM actions and resources.

Actions: case-insensitive, ``*`` matches any run of characters, ``?`` one.
Resources: case-sensitive, same wildcards. ``*`` crosses ``/`` and ``:``.
Policy variables such as ``${aws:username}`` cannot be resolved offline. They
are matched as ``*`` and the caller is told, so the statement is reported as
conditional instead of certain.
"""

from __future__ import annotations

import re
from functools import lru_cache

_VARIABLE_RE = re.compile(r"\$\{[^}]*\}")


def has_policy_variable(pattern: str) -> bool:
    return bool(_VARIABLE_RE.search(pattern))


@lru_cache(maxsize=8192)
def _compile(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        m = _VARIABLE_RE.match(pattern, i)
        if m:
            parts.append(".*")
            i = m.end()
            continue
        ch = pattern[i]
        if ch == "*":
            parts.append(".*")
        elif ch == "?":
            parts.append(".")
        else:
            parts.append(re.escape(ch))
        i += 1
    flags = re.DOTALL | (re.IGNORECASE if ignore_case else 0)
    return re.compile("".join(parts), flags)


def action_matches(pattern: str, action: str) -> bool:
    if pattern == "*":
        return True
    return _compile(pattern, True).fullmatch(action) is not None


def resource_matches(pattern: str, resource: str) -> bool:
    if pattern == "*":
        return True
    return _compile(pattern, False).fullmatch(resource) is not None
