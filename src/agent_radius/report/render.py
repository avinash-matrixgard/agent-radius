"""Render the report dict as Markdown and as self-contained HTML."""

from __future__ import annotations

import html
from typing import Any

HEADLINE = "What your agent could delete in 9 seconds"

_IRR_LABEL = {3: "irreversible", 2: "destructive", 1: "weakening"}


def _short(arn: str | None) -> str:
    from agent_radius.agents.ranking import short_arn

    return short_arn(arn)


def _md_escape(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(r: dict[str, Any]) -> str:
    s = r["summary"]
    out: list[str] = [
        f"# {HEADLINE}",
        "",
        f"Account `{r['account_id']}` ({', '.join(r['regions'])}), snapshot `{r['source']}`.",
        f"Agent principals: {', '.join(f'`{p}`' for p in r['agent_principals']) or 'none identified'}.",
        "",
        f"**{s['irreversible']} irreversible and {s['effective_destructive']} total destructive actions are open on"
        f" {s['resources_exposed']} resources. Backups: {s['at_risk']} AT_RISK, {s['partial']} PARTIAL,"
        f" {s['survives']} SURVIVE.**",
        "",
        "## Executive summary",
        "",
        r["executive_summary"],
        "",
        "## What the agent can destroy, ranked by irreversibility",
        "",
    ]
    items = r["headline_items"]
    if items:
        out += [
            "| # | Irreversibility | Action | Resource | Principal | Certainty | Severity | Guardrail blocks it | Evidence |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for it in items:
            out.append(
                f"| {it['rank']} | {it['irreversibility']} ({_IRR_LABEL.get(it['irreversibility'], '')}) | `{it['action']}` |"
                f" `{_md_escape(_short(it['resource']))}` | `{_md_escape(_short(it['principal']))}` | {it['certainty']} |"
                f" {it['severity']} | {it['guardrail_blocks']} | {', '.join(f'`{e}`' for e in it['evidence_ids'][:3])}"
                f"{' +' + str(len(it['evidence_ids']) - 3) if len(it['evidence_ids']) > 3 else ''} |"
            )
        out += ["", "Every line cites the policy statements the evaluator matched; full evidence is in `report.json`."]
    else:
        out.append("No destructive action is open to the agent principals.")

    out += ["", "## Would the backups survive?", ""]
    if r["backups"]:
        out += ["| Verdict | Resource | Principal | Why | Copies |", "|---|---|---|---|---|"]
        for b in r["backups"]:
            copies = "; ".join(f"{c['kind']} {c['status']}" for c in b["copies"]) or "none found"
            out.append(
                f"| **{b['verdict']}** | `{_md_escape(_short(b['resource']))}` | `{_md_escape(_short(b['principal']))}` |"
                f" {_md_escape(b['primary_reason'])} | {_md_escape(copies)} |"
            )
    else:
        out.append("No stateful resources were assessed.")

    if r["state_buckets"]:
        out += ["", "## Terraform state", ""]
        for t in r["state_buckets"]:
            out.append(f"- **{t['verdict']}** `{t['bucket']}`: {', '.join(t['problems']) or 'protected'}")

    out += ["", "## Credentials an agent process would inherit", ""]
    if r["credentials"]:
        for c in r["credentials"]:
            mapped = f"maps to `{_short(c['principal'])}` via {c['mapped_via']}" if c["principal"] else "not mapped"
            keys = ", ".join(c["key_names"]) or "no key names"
            out.append(f"- [{c['severity']}] `{c['path']}` ({c['source_type']}{', ' + c['detail'] if c['detail'] else ''}): {keys}; {mapped}")
        out.append("")
        out.append("Secret values are never read into the report; only file paths and key names are shown.")
    else:
        out.append("No credential sources were found or provided.")

    if r["blocked_by_resource_settings"]:
        out += ["", "## Granted by IAM but blocked by a resource setting", ""]
        for b in r["blocked_by_resource_settings"]:
            out.append(f"- `{b['action']}` on `{_short(b['resource'])}`: {'; '.join(b['notes'])}")

    g = r["guardrail"]
    out += [
        "",
        "## Guardrail",
        "",
        f"Terraform written to `guardrails/` (never applied): {', '.join(f'`{f}`' for f in g['files'])}.",
        f"What-if: with the generated deny policy attached, {g['what_if']['blocked']} of {g['what_if']['checked']}"
        " verified destructive IAM grants (including any already blocked by a resource setting) are denied on re-evaluation.",
    ]
    if g["what_if"].get("backup_verdicts_after"):
        after = ", ".join(f"{n} {v}" for v, n in sorted(g["what_if"]["backup_verdicts_after"].items()))
        out.append(f"Backup verdicts after the deny policy: {after}.")
    v = r["verification"]
    out += [
        "",
        "## Verification",
        "",
        f"- Findings posted by specialists: {v['posted']}; verified: {v['verified']}; dropped: {v['dropped']}.",
        f"- Structural HCL check: {v['hcl_check']['status']}.",
        f"- terraform validate: {v['terraform_validate']['status']}"
        + (f" ({v['terraform_validate']['reason']})" if v["terraform_validate"].get("reason") else "")
        + ".",
    ]
    if r["dropped_findings"]:
        out += ["", "### Dropped by the Verifier", ""]
        for d in r["dropped_findings"]:
            out.append(f"- `{d['finding_id']}` from {d['posted_by']}: {d['reason']}")
    if r["coverage_gaps"]:
        out += ["", "## Coverage gaps", ""] + [f"- {g_}" for g_ in r["coverage_gaps"]]
    out += ["", "## Agent trace", ""]
    for t in r["trace_summary"]:
        out.append(f"- {t}")
    out += ["", "## Limitations", ""] + [f"- {x}" for x in r["limitations"]]
    out.append("")
    return "\n".join(out)


_CSS = """
:root{--bg:#ffffff;--fg:#14171a;--muted:#5b6670;--line:#dde2e6;--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#4b5563;--ok:#15803d;--card:#f6f8fa}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0f1214;--fg:#e6e9ec;--muted:#9aa5ae;--line:#2a3036;--card:#171b1f;--crit:#f2827a;--high:#fb923c;--med:#facc15;--low:#9ca3af;--ok:#4ade80}}
:root[data-theme="dark"]{--bg:#0f1214;--fg:#e6e9ec;--muted:#9aa5ae;--line:#2a3036;--card:#171b1f;--crit:#f2827a;--high:#fb923c;--med:#facc15;--low:#9ca3af;--ok:#4ade80}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px 16px}
main{max-width:1100px;margin:0 auto}
h1{font-size:28px;margin:0 0 8px}h2{font-size:19px;margin:32px 0 8px;border-bottom:1px solid var(--line);padding-bottom:4px}
.meta{color:var(--muted)}.big{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:16px 0}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}
.critical{color:var(--crit);font-weight:600}.high{color:var(--high);font-weight:600}.medium{color:var(--med)}.low,.info{color:var(--low)}
.AT_RISK{color:var(--crit);font-weight:700}.PARTIAL{color:var(--high);font-weight:700}.SURVIVES{color:var(--ok);font-weight:700}
"""


def _e(x: Any) -> str:
    return html.escape(str(x), quote=True)


def render_html(r: dict[str, Any]) -> str:
    s = r["summary"]
    rows = []
    for it in r["headline_items"]:
        rows.append(
            "<tr>"
            f"<td>{it['rank']}</td><td>{it['irreversibility']}</td><td><code>{_e(it['action'])}</code></td>"
            f"<td><code>{_e(_short(it['resource']))}</code></td><td><code>{_e(_short(it['principal']))}</code></td>"
            f"<td>{_e(it['certainty'])}</td><td class=\"{_e(it['severity'])}\">{_e(it['severity'])}</td>"
            f"<td>{_e(it['guardrail_blocks'])}</td><td><code>{_e(', '.join(it['evidence_ids'][:3]))}</code></td>"
            "</tr>"
        )
    backups = []
    for b in r["backups"]:
        copies = "; ".join(f"{c['kind']} {c['status']}" for c in b["copies"]) or "none found"
        backups.append(
            f"<tr><td class=\"{_e(b['verdict'])}\">{_e(b['verdict'])}</td><td><code>{_e(_short(b['resource']))}</code></td>"
            f"<td><code>{_e(_short(b['principal']))}</code></td><td>{_e(b['primary_reason'])}</td><td>{_e(copies)}</td></tr>"
        )
    creds = "".join(
        f"<li>[{_e(c['severity'])}] <code>{_e(c['path'])}</code> ({_e(c['source_type'])}): {_e(', '.join(c['key_names']))}"
        f"{'; maps to <code>' + _e(_short(c['principal'])) + '</code>' if c['principal'] else '; not mapped'}</li>"
        for c in r["credentials"]
    )
    g = r["guardrail"]
    v = r["verification"]
    dropped = "".join(f"<li><code>{_e(d['finding_id'])}</code>: {_e(d['reason'])}</li>" for d in r["dropped_findings"])
    gaps = "".join(f"<li>{_e(x)}</li>" for x in r["coverage_gaps"])
    trace = "".join(f"<li>{_e(x)}</li>" for x in r["trace_summary"])
    head = (
        "<tr><th>#</th><th>Irrev.</th><th>Action</th><th>Resource</th><th>Principal</th><th>Certainty</th>"
        "<th>Severity</th><th>Guardrail blocks</th><th>Evidence</th></tr>"
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Radius Report</title><style>{_CSS}</style></head>
<body><main>
<h1>{_e(HEADLINE)}</h1>
<p class="meta">Account <code>{_e(r['account_id'])}</code> ({_e(', '.join(r['regions']))}). Agent principals: {_e(', '.join(r['agent_principals']) or 'none identified')}.</p>
<div class="big"><strong>{s['irreversible']} irreversible and {s['effective_destructive']} total destructive actions are open on {s['resources_exposed']} resources. Backups: {s['at_risk']} AT_RISK, {s['partial']} PARTIAL, {s['survives']} SURVIVE.</strong></div>
<h2>Executive summary</h2><p>{_e(r['executive_summary'])}</p>
<h2>What the agent can destroy, ranked by irreversibility</h2>
<div class="wrap"><table>{head}{''.join(rows) or '<tr><td colspan="9">No destructive action is open to the agent principals.</td></tr>'}</table></div>
<h2>Would the backups survive?</h2>
<div class="wrap"><table><tr><th>Verdict</th><th>Resource</th><th>Principal</th><th>Why</th><th>Copies</th></tr>{''.join(backups) or '<tr><td colspan="5">No stateful resources were assessed.</td></tr>'}</table></div>
<h2>Credentials an agent process would inherit</h2><ul>{creds or '<li>None found or provided.</li>'}</ul>
<p class="meta">Secret values are never read into the report; only file paths and key names are shown.</p>
<h2>Guardrail</h2><p>Files in <code>guardrails/</code> (never applied): {_e(', '.join(g['files']))}. What-if: the deny policy blocks {g['what_if']['blocked']} of {g['what_if']['checked']} verified destructive permissions.</p>
<h2>Verification</h2><p>Posted {v['posted']}, verified {v['verified']}, dropped {v['dropped']}. HCL check: {_e(v['hcl_check']['status'])}. terraform validate: {_e(v['terraform_validate']['status'])} {_e(v['terraform_validate'].get('reason', ''))}.</p>
<ul>{dropped}</ul>
<h2>Coverage gaps</h2><ul>{gaps or '<li>None recorded.</li>'}</ul>
<h2>Agent trace</h2><ul>{trace}</ul>
</main></body></html>
"""
