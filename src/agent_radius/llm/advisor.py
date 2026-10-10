"""The Advisor: the only place an LLM is consulted.

It may (a) reorder the plan's resource priority, (b) rank verified findings
by business impact, (c) write explanations and an executive summary. It can
never add, remove or alter a finding: outputs are keyed by existing ids,
validated against a JSON schema, and every ARN or action mentioned that is
not in the verified set is stripped and logged.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from agent_radius.agents.findings import Finding
from agent_radius.agents.ranking import deterministic_order, short_arn
from agent_radius.llm.base import LLMError
from agent_radius.llm.sanitize import UnsafePayload, safe_payload, strip_unverified
from agent_radius.llm.schema import SchemaError, validate

PLAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "priority_resources": {"type": "array", "items": {"type": "string"}, "maxItems": 2000},
        "rationale": {"type": "string", "maxLength": 2000},
    },
    "required": ["priority_resources", "rationale"],
    "additionalProperties": False,
}
RANK_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "ranking": {
            "type": "array",
            "maxItems": 5000,
            "items": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string"},
                    "business_impact": {"type": "string", "maxLength": 600},
                },
                "required": ["finding_id", "business_impact"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["ranking"],
    "additionalProperties": False,
}
EXPLAIN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "explanations": {
            "type": "array",
            "maxItems": 5000,
            "items": {
                "type": "object",
                "properties": {"finding_id": {"type": "string"}, "text": {"type": "string", "maxLength": 1200}},
                "required": ["finding_id", "text"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["explanations"],
    "additionalProperties": False,
}
SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"executive_summary": {"type": "string", "maxLength": 4000}},
    "required": ["executive_summary"],
    "additionalProperties": False,
}

SYSTEM = (
    "You are a cloud security analyst reviewing verified findings from Agent Radius, a read-only auditor."
    " The findings are final. Never invent findings, resources, principals or actions. Refer only to ids,"
    " ARNs and IAM actions that appear in the input. State conditional results as possible, never certain."
)

MAX_SENT = 300

Log = Callable[[str, str], None]


def brief(f: Finding) -> dict[str, Any]:
    """The only view of a finding an LLM ever sees."""
    out: dict[str, Any] = {
        "id": f.id,
        "kind": f.kind,
        "title": f.title,
        "severity": f.severity,
        "principal": f.principal,
        "action": f.action,
        "resource": f.resource,
        "outcome": f.outcome,
        "verdict": f.verdict,
        "certainty": f.certainty,
        "irreversibility": f.irreversibility,
        "effective": f.effective,
        "env": f.env,
        "consequence": f.consequence,
        "notes": list(f.data.get("notes", []))[:6],
    }
    if f.kind == "local_credential":
        out["source_type"] = f.data.get("source_type")
        out["path"] = f.data.get("path")
        out["key_names"] = f.data.get("key_names")
    return out


def deterministic_explanation(f: Finding) -> str:
    who = short_arn(f.principal)
    if f.kind == "destructive_permission":
        text = f"{who} can call {f.action} on {short_arn(f.resource)}. {f.consequence}"
        if f.certainty == "possible":
            why = "; ".join(f.data.get("conditions", [])) or "a condition"
            text += f" This is possible, not certain: it depends on {why}."
        if not f.effective:
            text += " In practice it is blocked: " + "; ".join(f.data.get("notes", [])) + "."
        return text
    if f.kind in ("backup_survivability", "state_bucket"):
        copies = f.data.get("assessment", {}).get("copies", [])
        safe = [c for c in copies if c["status"] == "SAFE"]
        text = f"{f.verdict}: for {who}, {f.data.get('assessment', {}).get('primary_reason', '')}."
        if not copies:
            text += " No backup copy was found."
        elif safe:
            text += f" {len(safe)} of {len(copies)} copies survive ({safe[0]['reason']})."
        else:
            text += f" None of the {len(copies)} copies survive this agent."
        return text
    if f.kind == "local_credential":
        mapped = f" and maps to {who}" if f.principal else ", but could not be mapped to a principal"
        return f"{f.data.get('source_type')} at {f.data.get('path')} is visible to any agent process{mapped}."
    return f.title


class Advisor:
    def __init__(self, backend: Any, log: Log | None = None) -> None:
        self.backend = backend
        self._log = log or (lambda event, detail: None)
        self.stripped: list[dict[str, Any]] = []
        self.errors: list[str] = []

    @property
    def enabled(self) -> bool:
        return getattr(self.backend, "name", "none") != "none"

    def _call(self, role: str, prompt_obj: Any, schema: dict[str, Any], instruction: str) -> Any:
        try:
            prompt = instruction + "\n\nINPUT:\n" + safe_payload(prompt_obj)
        except UnsafePayload as exc:
            self.errors.append(str(exc))
            self._log("llm", f"refused to send payload: {exc}")
            raise LLMError(str(exc)) from exc
        result = self.backend.complete_json(role=role, system=SYSTEM, prompt=prompt, schema=schema)
        try:
            validate(result, schema)
        except SchemaError as exc:
            raise LLMError(f"schema violation: {exc}") from exc
        return result

    def _strip(self, text: str, allowed_arns: set[str], allowed_actions: set[str], where: str) -> str:
        clean, removed = strip_unverified(text, allowed_arns, allowed_actions)
        for item in removed:
            self.stripped.append({"where": where, "removed": item})
            self._log("llm_strip", f"{where}: removed unverified reference {item}")
        return clean

    # ---- (a) plan --------------------------------------------------------------

    def reprioritise_plan(self, order: list[str], context: list[dict[str, Any]]) -> tuple[list[str], str, bool]:
        default_reason = "deterministic: prod-tagged or prod-named resources first, then unknown, then non-prod"
        if not self.enabled or not order:
            return order, default_reason, False
        try:
            result = self._call(
                "planner",
                {"resources": context},
                PLAN_SCHEMA,
                "Reorder priority_resources so the resources whose loss would hurt the business most come first."
                " Return every resource ARN exactly once.",
            )
        except LLMError as exc:
            self.errors.append(f"plan: {exc}")
            self._log("llm", f"plan fell back to deterministic order ({exc})")
            return order, default_reason, False
        known = set(order)
        new: list[str] = []
        for arn in result["priority_resources"]:
            if arn not in known:
                self.stripped.append({"where": "plan", "removed": arn})
                self._log("llm_strip", f"plan: ignored unknown resource {arn}")
                continue
            if arn not in new:
                new.append(arn)
        new += [arn for arn in order if arn not in new]
        rationale = self._strip(result["rationale"], known, set(), "plan.rationale")
        return new, rationale, new != order

    # ---- (b) rank --------------------------------------------------------------

    def rank(self, findings: list[Finding], priority: dict[str, int] | None = None) -> tuple[list[str], dict[str, str]]:
        base = [f.id for f in deterministic_order(findings, priority)]
        if not self.enabled or not findings:
            return base, {}
        by_id = {f.id: f for f in findings}
        allowed_arns = {a for f in findings for a in (f.resource, f.principal) if a}
        allowed_actions = {f.action for f in findings if f.action}
        sent = [brief(by_id[i]) for i in base[:MAX_SENT]]
        try:
            result = self._call(
                "worker",
                {"findings": sent},
                RANK_SCHEMA,
                "Rank these findings by business impact (most damaging first) and give a one-sentence"
                " business_impact for each. Use only the given finding ids.",
            )
        except LLMError as exc:
            self.errors.append(f"rank: {exc}")
            self._log("llm", f"ranking fell back to deterministic order ({exc})")
            return base, {}
        order: list[str] = []
        impacts: dict[str, str] = {}
        for item in result["ranking"]:
            fid = item["finding_id"]
            if fid not in by_id:
                self.stripped.append({"where": "rank", "removed": fid})
                self._log("llm_strip", f"rank: ignored unknown finding id {fid}")
                continue
            if fid in order:
                continue
            order.append(fid)
            impacts[fid] = self._strip(item["business_impact"], allowed_arns, allowed_actions, f"rank.{fid}")
        order += [i for i in base if i not in order]
        return order, impacts

    # ---- (c) explain + summarise -------------------------------------------------

    def explain(self, findings: list[Finding], headline_stats: dict[str, Any]) -> tuple[dict[str, str], str]:
        explanations = {f.id: deterministic_explanation(f) for f in findings}
        summary = deterministic_summary(headline_stats)
        if not self.enabled or not findings:
            return explanations, summary
        by_id = {f.id: f for f in findings}
        allowed_arns = {a for f in findings for a in (f.resource, f.principal) if a}
        allowed_actions = {f.action for f in findings if f.action}
        sent = [brief(f) for f in deterministic_order(findings)[:MAX_SENT]]
        try:
            result = self._call(
                "worker",
                {"findings": sent},
                EXPLAIN_SCHEMA,
                "For each finding write two plain-English sentences a startup CTO would understand: what the"
                " agent could do and why it matters. Keep conditional findings framed as possible.",
            )
            for item in result["explanations"]:
                fid = item["finding_id"]
                if fid not in by_id:
                    self.stripped.append({"where": "explain", "removed": fid})
                    self._log("llm_strip", f"explain: ignored unknown finding id {fid}")
                    continue
                explanations[fid] = self._strip(item["text"], allowed_arns, allowed_actions, f"explain.{fid}")
        except LLMError as exc:
            self.errors.append(f"explain: {exc}")
            self._log("llm", f"explanations fell back to templates ({exc})")
        try:
            result = self._call(
                "summary",
                {"stats": headline_stats, "top_findings": sent[:25]},
                SUMMARY_SCHEMA,
                "Write a five-sentence executive summary of what an AI coding agent with these credentials could"
                " destroy, whether backups survive, and the first guardrail to apply.",
            )
            summary = self._strip(result["executive_summary"], allowed_arns, allowed_actions, "summary")
        except LLMError as exc:
            self.errors.append(f"summary: {exc}")
            self._log("llm", f"summary fell back to template ({exc})")
        return explanations, summary


def deterministic_summary(stats: dict[str, Any]) -> str:
    parts = [
        f"Agent Radius found {stats.get('effective_destructive', 0)} destructive actions the agent credentials"
        f" can perform on {stats.get('resources_exposed', 0)} resources"
        f" ({stats.get('irreversible', 0)} of them irreversible).",
        f"Backups: {stats.get('at_risk', 0)} resources AT_RISK, {stats.get('partial', 0)} PARTIAL,"
        f" {stats.get('survives', 0)} SURVIVE.",
    ]
    if stats.get("conditional"):
        parts.append(f"{stats['conditional']} further actions are possible but depend on conditions Agent Radius cannot evaluate offline.")
    if stats.get("blocked_by_guardrail") is not None:
        parts.append(
            f"The generated deny policy blocks {stats['blocked_by_guardrail']} of"
            f" {stats.get('guardrail_checked', 0)} verified destructive permissions in the what-if re-evaluation."
        )
    if stats.get("dropped"):
        parts.append(f"The Verifier dropped {stats['dropped']} findings that did not reproduce.")
    return " ".join(parts)
