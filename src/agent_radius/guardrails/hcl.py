"""Minimal HCL rendering and a structural sanity checker.

``render_value`` turns a JSON-compatible value into an HCL expression (the
argument we wrap in ``jsonencode(...)``). ``parse_value`` parses that subset
back, so the checker can prove the policy inside every ``jsonencode`` round
trips to the exact JSON we rendered. ``check_hcl`` is not Terraform: it
catches unbalanced delimiters, unterminated strings, malformed top-level
blocks and non-policy ``jsonencode`` payloads. ``terraform validate`` is run
on top of it when Terraform is installed.
"""

from __future__ import annotations

import json
import re
from typing import Any

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


class HclError(ValueError):
    pass


def hcl_string(value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
        .replace("${", "$${")
        .replace("%{", "%%{")
    )
    return f'"{escaped}"'


def _key(key: str) -> str:
    return key if _IDENT_RE.match(key) else hcl_string(key)


def render_value(value: Any, indent: int = 0) -> str:
    pad = "  " * indent
    inner = "  " * (indent + 1)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    if isinstance(value, str):
        return hcl_string(value)
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(isinstance(v, str) for v in value) and len(value) <= 3:
            return "[" + ", ".join(hcl_string(v) for v in value) + "]"
        items = [f"{inner}{render_value(v, indent + 1)}," for v in value]
        return "[\n" + "\n".join(items) + f"\n{pad}]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        width = max(len(_key(k)) for k in value)
        lines = [f"{inner}{_key(k).ljust(width)} = {render_value(v, indent + 1)}" for k, v in value.items()]
        return "{\n" + "\n".join(lines) + f"\n{pad}}}"
    raise HclError(f"cannot render {type(value).__name__}")


# --------------------------------------------------------------------------
# Parser for the rendered subset
# --------------------------------------------------------------------------


class _Parser:
    def __init__(self, text: str) -> None:
        self.text = text
        self.i = 0

    def ws(self) -> None:
        while self.i < len(self.text):
            ch = self.text[self.i]
            if ch in " \t\r\n,":
                self.i += 1
            elif self.text.startswith("#", self.i) or self.text.startswith("//", self.i):
                while self.i < len(self.text) and self.text[self.i] != "\n":
                    self.i += 1
            else:
                break

    def value(self) -> Any:
        self.ws()
        if self.i >= len(self.text):
            raise HclError("unexpected end of input")
        ch = self.text[self.i]
        if ch == "{":
            return self.obj()
        if ch == "[":
            return self.arr()
        if ch == '"':
            return self.string()
        for word, val in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.i):
                self.i += len(word)
                return val
        m = re.compile(r"-?\d+(\.\d+)?([eE][+-]?\d+)?").match(self.text, self.i)
        if m:
            self.i = m.end()
            return json.loads(m.group(0))
        raise HclError(f"unsupported expression at offset {self.i}: {self.text[self.i:self.i + 20]!r}")

    def string(self) -> str:
        assert self.text[self.i] == '"'
        self.i += 1
        out = []
        while self.i < len(self.text):
            ch = self.text[self.i]
            if ch == '"':
                self.i += 1
                return "".join(out)
            if ch == "\\":
                nxt = self.text[self.i + 1]
                out.append({"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}.get(nxt, nxt))
                self.i += 2
                continue
            if self.text.startswith("$${", self.i):
                out.append("${")
                self.i += 3
                continue
            if self.text.startswith("%%{", self.i):
                out.append("%{")
                self.i += 3
                continue
            if self.text.startswith("${", self.i) or self.text.startswith("%{", self.i):
                raise HclError("template interpolation inside a policy literal")
            out.append(ch)
            self.i += 1
        raise HclError("unterminated string")

    def arr(self) -> list[Any]:
        self.i += 1
        out = []
        while True:
            self.ws()
            if self.i >= len(self.text):
                raise HclError("unterminated list")
            if self.text[self.i] == "]":
                self.i += 1
                return out
            out.append(self.value())

    def obj(self) -> dict[str, Any]:
        self.i += 1
        out: dict[str, Any] = {}
        while True:
            self.ws()
            if self.i >= len(self.text):
                raise HclError("unterminated object")
            if self.text[self.i] == "}":
                self.i += 1
                return out
            if self.text[self.i] == '"':
                key = self.string()
            else:
                m = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*").match(self.text, self.i)
                if not m:
                    raise HclError(f"bad object key at offset {self.i}")
                key = m.group(0)
                self.i = m.end()
            self.ws()
            if self.i < len(self.text) and self.text[self.i] in "=:":
                self.i += 1
            else:
                raise HclError(f"expected = after key {key!r}")
            out[key] = self.value()


def parse_value(text: str) -> Any:
    p = _Parser(text)
    value = p.value()
    p.ws()
    if p.i != len(text):
        raise HclError(f"trailing content at offset {p.i}")
    return value


# --------------------------------------------------------------------------
# Structural checker
# --------------------------------------------------------------------------

_BLOCK_LABELS = {
    "resource": 2,
    "data": 2,
    "variable": 1,
    "output": 1,
    "provider": 1,
    "module": 1,
    "terraform": 0,
    "locals": 0,
}


def _strip_strings_and_comments(text: str) -> tuple[str, list[str]]:
    """Blank out string contents and comments; report unterminated strings."""
    out = []
    problems = []
    i = 0
    line = 1
    while i < len(text):
        ch = text[i]
        if ch == "\n":
            line += 1
        if ch == "#" or text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                problems.append(f"line {line}: unterminated block comment")
                break
            line += text.count("\n", i, end)
            out.append(" " * (end + 2 - i))
            i = end + 2
            continue
        if ch == '"':
            j = i + 1
            while j < len(text) and text[j] != '"':
                if text[j] == "\\":
                    j += 1
                if j < len(text) and text[j] == "\n":
                    problems.append(f"line {line}: newline inside a quoted string")
                    break
                j += 1
            if j >= len(text):
                problems.append(f"line {line}: unterminated string")
                break
            out.append('""')
            i = j + 1
            continue
        out.append(ch)
        i += 1
    return "".join(out), problems


def _jsonencode_args(text: str) -> list[str]:
    args = []
    for m in re.finditer(r"jsonencode\(", text):
        start = m.end()
        depth = 1
        i = start
        in_str = False
        while i < len(text) and depth:
            ch = text[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            i += 1
        args.append(text[start : i - 1])
    return args


def _policy_shape_problems(doc: Any) -> list[str]:
    if not isinstance(doc, dict):
        return ["jsonencode argument is not an object"]
    problems = []
    if doc.get("Version") != "2012-10-17":
        problems.append("policy Version must be 2012-10-17")
    stmts = doc.get("Statement")
    if not isinstance(stmts, list) or not stmts:
        problems.append("policy Statement must be a non-empty list")
        return problems
    for i, st in enumerate(stmts):
        if not isinstance(st, dict):
            problems.append(f"Statement[{i}] is not an object")
            continue
        if st.get("Effect") not in ("Allow", "Deny"):
            problems.append(f"Statement[{i}] Effect must be Allow or Deny")
        if not ({"Action", "NotAction"} & set(st)):
            problems.append(f"Statement[{i}] has no Action or NotAction")
        if not ({"Resource", "NotResource"} & set(st)):
            problems.append(f"Statement[{i}] has no Resource or NotResource")
        actions = st.get("Action", [])
        if isinstance(actions, list) and not actions:
            problems.append(f"Statement[{i}] has an empty Action list")
    return problems


def check_hcl(text: str, expected_policies: list[dict[str, Any]] | None = None) -> list[str]:
    """Return a list of structural problems (empty means it passed)."""
    stripped, problems = _strip_strings_and_comments(text)
    pairs = {"}": "{", "]": "[", ")": "("}
    stack: list[tuple[str, int]] = []
    line = 1
    for ch in stripped:
        if ch == "\n":
            line += 1
        elif ch in "{[(":
            stack.append((ch, line))
        elif ch in "}])":
            if not stack or stack[-1][0] != pairs[ch]:
                problems.append(f"line {line}: unbalanced {ch!r}")
                return problems
            stack.pop()
    for ch, ln in stack:
        problems.append(f"line {ln}: {ch!r} is never closed")

    # Top-level blocks: track depth on the stripped text.
    depth = 0
    for ln_no, raw in enumerate(stripped.splitlines(), start=1):
        s = raw.strip()
        if depth == 0 and s:
            m = re.match(r"^([a-z_]+)((?:\s+\"\")*)\s*\{\s*\}?\s*$", s)
            if not m:
                problems.append(f"line {ln_no}: expected a top-level block, got {s[:40]!r}")
            else:
                kind = m.group(1)
                labels = m.group(2).count('""')
                if kind not in _BLOCK_LABELS:
                    problems.append(f"line {ln_no}: unknown top-level block {kind!r}")
                elif _BLOCK_LABELS[kind] != labels:
                    problems.append(f"line {ln_no}: {kind} block needs {_BLOCK_LABELS[kind]} labels, has {labels}")
        depth += raw.count("{") - raw.count("}")

    # Every jsonencode payload must parse and look like an IAM policy.
    parsed = []
    for arg in _jsonencode_args(text):
        try:
            value = parse_value(arg.strip())
        except HclError as exc:
            problems.append(f"jsonencode argument does not parse: {exc}")
            continue
        parsed.append(value)
        problems += _policy_shape_problems(value)
    if expected_policies is not None:
        for doc in expected_policies:
            if doc not in parsed:
                problems.append("a rendered policy does not round-trip through its jsonencode block")
    return problems
