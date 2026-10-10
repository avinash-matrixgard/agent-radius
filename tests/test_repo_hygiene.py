"""Repository rules: no em dash anywhere, CLAUDE.md stays short."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EM_DASH = chr(0x2014)  # built at runtime so this file never contains the character
SKIP_DIRS = {".venv", ".git", "__pycache__", ".pytest_cache", ".ruff_cache", "agent-radius-out"}


def _files():
    for p in ROOT.rglob("*"):
        if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_DIRS) and p.name != "LICENSE":
            yield p


def test_no_em_dash_anywhere():
    offenders = []
    for p in _files():
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if EM_DASH in text:
            offenders.append(str(p.relative_to(ROOT)))
    assert not offenders, offenders


def test_claude_md_is_short():
    path = ROOT / "CLAUDE.md"
    if path.exists():
        assert len(path.read_text().splitlines()) <= 200
