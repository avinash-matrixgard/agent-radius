#!/usr/bin/env python3
"""Draw docs/assets/demo.svg from the real output of ``agent-radius demo``.

What it does:

1. Runs the demo exactly as a user would (``python -m agent_radius demo``,
   from the repository root, default output directory) and captures stdout.
2. Prints every captured line, unedited, into a recording rich Console.
3. Exports that recording with ``Console.export_svg`` as a terminal window
   titled "agent-radius demo", on a solid MatrixGard dark background.

What it changes, and nothing else:

- A prompt line ``$ agent-radius demo`` is drawn above the output.
- A few tokens are coloured (the headline, AT_RISK, critical, high, action
  names). The text itself is never edited.
- Lines longer than WIDTH columns word-wrap, as they would in a terminal of
  that width. No text is removed.
- If the output ever grows past MAX_LINES lines, only the first MAX_LINES are
  drawn, followed by one line that says how many were left out. Today the
  demo prints far fewer, so the whole output is drawn.
- The SVG loads no web fonts: it names a local monospace stack only.
- Text is marked xml:space="preserve" so every renderer keeps the column
  alignment (librsvg otherwise collapses the non-breaking spaces rich emits).

Usage (needs the dev extras, which include rich):

    uv pip install -e ".[dev]"
    .venv/bin/python scripts/render_demo_svg.py            # writes docs/assets/demo.svg
    .venv/bin/python scripts/render_demo_svg.py --out x.svg
"""

from __future__ import annotations

import argparse
import io
import re
import subprocess
import sys
from pathlib import Path

from rich.console import Console
from rich.terminal_theme import TerminalTheme
from rich.text import Text

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "docs" / "assets" / "demo.svg"
TITLE = "agent-radius demo"
PROMPT = "$ agent-radius demo"
WIDTH = 112  # columns; only longer lines wrap
MAX_LINES = 60  # draw at most this many output lines
PAD = 24  # dark margin around the window, in px
# Glyph width / font size for SF Mono, Menlo and DejaVu Sans Mono (rich assumes Fira Code).
FONT_ASPECT = 0.6

# MatrixGard palette.
GROUND = "#0A0A0B"
WINDOW = "#141418"
TEXT = "#E5E7EB"
ORANGE = "#FF8A3D"
GOLD = "#F5C16C"
MUTED = "#9CA3AF"

THEME = TerminalTheme(
    (20, 20, 24),  # window background (WINDOW)
    (229, 231, 235),  # default text (TEXT)
    [
        (20, 20, 24),
        (255, 138, 61),
        (156, 163, 175),
        (245, 193, 108),
        (156, 163, 175),
        (255, 138, 61),
        (156, 163, 175),
        (229, 231, 235),
    ],
)

# (regex, style). Applied in order; later rules win where they overlap.
HIGHLIGHTS: list[tuple[str, str]] = [
    (r"^Demo:.*$", MUTED),
    (r"^[A-Z0-9 ]{12,}$", f"bold {ORANGE}"),  # the upper-case headline
    (r"^=+$", ORANGE),
    (r"\[irr \d\]", MUTED),
    (r"\b[a-z0-9-]+:[A-Z][A-Za-z]+\b", f"bold {TEXT}"),  # IAM action names
    (r"\bhigh\b", GOLD),
    (r"\bcritical\b", ORANGE),
    (r"\bAT_RISK\b", f"bold {ORANGE}"),
    (r"^(Reports|Guardrails \(not applied\)|Verifier):", f"bold {GOLD}"),
]

INNER_FORMAT = """<svg x="{pad}" y="{pad}" width="{{width}}" height="{{height}}" viewBox="0 0 {{width}} {{height}}">
    <style>
    .{{unique_id}}-matrix {{{{
        font-family: SFMono-Regular, Menlo, Consolas, "Liberation Mono", "DejaVu Sans Mono", monospace;
        font-size: {{char_height}}px;
        line-height: {{line_height}}px;
        font-variant-east-asian: full-width;
    }}}}
    .{{unique_id}}-title {{{{
        font-size: 16px;
        font-weight: 600;
        font-family: Inter, -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    }}}}
    {{styles}}
    </style>
    <defs>
    <clipPath id="{{unique_id}}-clip-terminal">
      <rect x="0" y="0" width="{{terminal_width}}" height="{{terminal_height}}" />
    </clipPath>
    {{lines}}
    </defs>
    {{chrome}}
    <g transform="translate({{terminal_x}}, {{terminal_y}})" clip-path="url(#{{unique_id}}-clip-terminal)">
    {{backgrounds}}
    <g class="{{unique_id}}-matrix" xml:space="preserve" style="white-space: pre">
    {{matrix}}
    </g>
    </g>
</svg>""".format(pad=PAD)


def run_demo() -> list[str]:
    proc = subprocess.run(
        [sys.executable, "-m", "agent_radius", "demo"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    lines = proc.stdout.splitlines()
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def styled(line: str) -> Text:
    text = Text(line)
    for pattern, style in HIGHLIGHTS:
        text.highlight_regex(re.compile(pattern), style=style)
    return text


def render(lines: list[str]) -> str:
    shown = lines[:MAX_LINES]
    console = Console(
        record=True,
        width=WIDTH,
        file=io.StringIO(),
        force_terminal=True,
        color_system="truecolor",
        highlight=False,
    )
    prompt = Text(PROMPT)
    prompt.stylize(f"bold {ORANGE}", 0, 1)
    prompt.stylize(f"bold {TEXT}", 2)
    console.print(prompt)
    for line in shown:
        console.print(styled(line), overflow="fold")
    if len(lines) > len(shown):
        left_out = len(lines) - len(shown)
        console.print(
            Text(
                f"... {left_out} more lines not drawn here; run the command to see them all.",
                style=MUTED,
            )
        )
    inner = console.export_svg(
        title=TITLE,
        theme=THEME,
        code_format=INNER_FORMAT,
        font_aspect_ratio=FONT_ASPECT,
        unique_id="agent-radius-demo",
    )
    m = re.search(r'width="([\d.]+)" height="([\d.]+)"', inner)
    if not m:
        raise SystemExit("could not read the size rich exported")
    w = round(float(m.group(1)) + 2 * PAD)
    h = round(float(m.group(2)) + 2 * PAD)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
        f'role="img" aria-label="Terminal output of agent-radius demo">\n'
        f"<title>{TITLE}</title>\n"
        "<!-- Generated by scripts/render_demo_svg.py from the real output of agent-radius demo. Do not edit by hand. -->\n"
        f'<rect x="0" y="0" width="{w}" height="{h}" fill="{GROUND}"/>\n'
        f"{inner}\n</svg>\n"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", default=str(DEFAULT_OUT), help="Where to write the SVG.")
    args = parser.parse_args(argv)
    lines = run_demo()
    svg = render(lines)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(svg, encoding="utf-8")
    drawn = min(len(lines), MAX_LINES)
    print(f"demo printed {len(lines)} lines; drew {drawn}; wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
