"""LLM backends are tested with fakes only. No network, no paid calls."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent_radius.agents.orchestrator import RunOptions, run_scan
from agent_radius.agents.recon_scan import ReconPaths, fingerprint_access_key_id
from agent_radius.llm import LLMError, ModelConfig, make_backend
from agent_radius.llm.anthropic_backend import FALLBACK_BETA, AnthropicBackend
from agent_radius.llm.claude_cli_backend import ClaudeCliBackend
from agent_radius.llm.sanitize import UNVERIFIED, UnsafePayload, safe_payload, strip_unverified
from agent_radius.llm.schema import SchemaError, validate
from tests.helpers import ADMIN, make, rds_arn, role, role_arn, user, user_arn

DB = rds_arn("prod-db")
FAKE_DB = rds_arn("billing-db-invented")
SECRET = "TestFixture/SecretNotReal/00000000000001"
KEY_ID = "AKIATESTFIXTUREXYZ12"


def test_schema_validator():
    schema = {"type": "object", "properties": {"a": {"type": "array", "items": {"type": "string"}, "maxItems": 2}},
              "required": ["a"], "additionalProperties": False}
    validate({"a": ["x"]}, schema)
    for bad in ({}, {"a": [1]}, {"a": ["x", "y", "z"]}, {"a": [], "b": 1}, []):
        with pytest.raises(SchemaError):
            validate(bad, schema)


def test_strip_unverified_keeps_known_and_removes_unknown():
    text = f"Delete {DB} and {FAKE_DB}. Calls rds:DeleteDBInstance and rds:DeleteDBCluster. Time 10:30, note: OK."
    clean, removed = strip_unverified(text, {DB}, {"rds:DeleteDBInstance"})
    assert DB in clean and FAKE_DB not in clean
    assert "rds:DeleteDBInstance" in clean and "rds:DeleteDBCluster" not in clean
    assert sorted(removed) == sorted([FAKE_DB, "rds:DeleteDBCluster"])
    assert "10:30" in clean and UNVERIFIED in clean


def test_safe_payload_scrubs_and_refuses():
    text = safe_payload({"path": "~/.cursor/mcp.json", "note": f"key {KEY_ID}"})
    assert KEY_ID not in text and "REDACTED" in text
    import agent_radius.llm.sanitize as san

    original = san.scrub
    try:
        san.scrub = lambda x: x  # simulate a broken scrubber: the second check must still refuse
        with pytest.raises(UnsafePayload):
            san.safe_payload({"secret": SECRET})
    finally:
        san.scrub = original


class FakeAnthropicClient:
    def __init__(self, reply, stop_reason="end_turn"):
        self.calls = []
        self.reply = reply
        self.stop_reason = stop_reason
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.calls.append(kwargs)
                return SimpleNamespace(stop_reason=outer.stop_reason, content=[SimpleNamespace(type="text", text=outer.reply)])

        self.messages = _Messages()
        self.beta = SimpleNamespace(messages=_Messages())


def test_anthropic_backend_request_shape_and_parsing():
    client = FakeAnthropicClient('{"executive_summary": "ok"}')
    backend = AnthropicBackend(models=ModelConfig(), client=client)
    schema = {"type": "object"}
    assert backend.complete_json(role="summary", system="sys", prompt="p", schema=schema) == {"executive_summary": "ok"}
    backend.complete_json(role="worker", system="sys", prompt="p", schema=schema)
    first, second = client.calls
    assert first["model"] == "claude-opus-5-5" and second["model"] == "claude-sonnet-5-5"
    assert first["output_config"]["format"] == {"type": "json_schema", "schema": schema}
    assert first["betas"] == [FALLBACK_BETA] and first["fallbacks"] == "default"
    assert first["messages"] == [{"role": "user", "content": "p"}]


def test_anthropic_backend_refusal_and_bad_json_raise():
    with pytest.raises(LLMError):
        AnthropicBackend(client=FakeAnthropicClient("{}", stop_reason="refusal")).complete_json(role="worker", system="", prompt="", schema={})
    with pytest.raises(LLMError):
        AnthropicBackend(client=FakeAnthropicClient("not json")).complete_json(role="worker", system="", prompt="", schema={})


def test_claude_cli_backend_uses_stdin_and_parses_envelope():
    seen = {}

    def runner(cmd, **kw):
        seen["cmd"], seen["input"] = cmd, kw["input"]
        envelope = {"type": "result", "is_error": False, "result": '```json\n{"ranking": []}\n```'}
        return SimpleNamespace(returncode=0, stdout=json.dumps(envelope), stderr="")

    backend = ClaudeCliBackend(models=ModelConfig(worker="claude-sonnet-5-5"), runner=runner)
    assert backend.complete_json(role="worker", system="SYS", prompt="PROMPT", schema={"type": "object"}) == {"ranking": []}
    assert seen["cmd"] == ["claude", "-p", "--model", "claude-sonnet-5-5", "--output-format", "json"]
    assert "PROMPT" in seen["input"] and "SYS" in seen["input"]
    assert "PROMPT" not in " ".join(seen["cmd"])


def test_claude_cli_backend_errors():
    bad_exit = ClaudeCliBackend(runner=lambda cmd, **kw: SimpleNamespace(returncode=1, stdout="", stderr="x"))
    with pytest.raises(LLMError):
        bad_exit.complete_json(role="worker", system="", prompt="", schema={})
    is_error = ClaudeCliBackend(runner=lambda cmd, **kw: SimpleNamespace(returncode=0, stdout='{"is_error": true}', stderr=""))
    with pytest.raises(LLMError):
        is_error.complete_json(role="worker", system="", prompt="", schema={})


def test_make_backend():
    assert make_backend("none").name == "none"
    assert make_backend("anthropic", client=object()).name == "anthropic"
    assert make_backend("claude-cli").name == "claude-cli"
    with pytest.raises(ValueError):
        make_backend("gpt")


class HallucinatingBackend:
    """Tries every trick: invented findings, invented ARNs, invented actions."""

    name = "fake-llm"

    def __init__(self):
        self.prompts = []

    def complete_json(self, *, role, system, prompt, schema):
        self.prompts.append((role, prompt))
        payload = json.loads(prompt.split("INPUT:\n", 1)[1])
        if "resources" in payload:
            arns = [r["arn"] for r in payload["resources"]]
            return {"priority_resources": [FAKE_DB] + list(reversed(arns)), "rationale": f"start with {FAKE_DB}"}
        if "stats" in payload:
            return {"executive_summary": f"The agent can also wipe {FAKE_DB} via rds:DeleteDBCluster."}
        ids = [f["id"] for f in payload["findings"]]
        if "business_impact" in json.dumps(schema):
            return {"ranking": [{"finding_id": "perm-invented00", "business_impact": "made up"}]
                    + [{"finding_id": i, "business_impact": f"hits {FAKE_DB}"} for i in reversed(ids)]}
        return {"explanations": [{"finding_id": "perm-invented00", "text": "new finding"}]
                + [{"finding_id": i, "text": f"also see {FAKE_DB}"} for i in ids]}


def _scan_with(backend, tmp_path, recon=None):
    snap = make(
        users=[user("ci-admin", attached=[ADMIN])],
        roles=[role("agent", attached=[ADMIN])],
        resources={"rds_instances": [{"identifier": "prod-db", "arn": DB, "tags": {"env": "prod"}},
                                     {"identifier": "dev-db", "arn": rds_arn("dev-db")}]},
        agent_principals=[role_arn("agent")],
        access_key_fingerprints={fingerprint_access_key_id(KEY_ID): user_arn("ci-admin")},
    )
    return run_scan(snap, RunOptions(out_dir=tmp_path, backend=backend, recon_paths=recon, terraform_bin=None))


def test_llm_cannot_create_findings_or_mention_unverified_arns(tmp_path):
    baseline = _scan_with(make_backend("none"), tmp_path / "none")
    backend = HallucinatingBackend()
    board = _scan_with(backend, tmp_path / "llm")
    assert {f.id for f in board.verified} == {f.id for f in baseline.verified}
    reported_ids = {f["id"] for f in board.report["findings"]} | {i["finding_id"] for i in board.report["headline_items"]}
    assert "perm-invented00" not in reported_ids
    # User-facing content never carries the invented ARN; only the audit log of removals names it.
    user_facing = (tmp_path / "llm" / "report.md").read_text() + (tmp_path / "llm" / "report.html").read_text()
    user_facing += json.dumps([board.report[k] for k in ("findings", "headline_items", "backups", "executive_summary", "plan")])
    assert FAKE_DB not in user_facing
    assert any(f["explanation"].startswith("also see [removed") for f in board.report["findings"] if f["kind"] != "guardrail")
    assert "rds:DeleteDBCluster" not in board.report["executive_summary"]
    removed = {s["removed"] for s in board.report["llm"]["stripped"]}
    assert FAKE_DB in removed and "perm-invented00" in removed and "rds:DeleteDBCluster" in removed
    assert board.plan.llm_adjusted and FAKE_DB not in board.plan.resource_priority
    assert sorted(board.plan.resource_priority) == sorted(baseline.plan.resource_priority)
    assert any(t.event == "llm_strip" for t in board.trace)
    roles = {r for r, _ in backend.prompts}
    assert roles == {"planner", "worker", "summary"}


def test_secrets_never_reach_the_llm(tmp_path):
    home = tmp_path / "home"
    (home / ".cursor").mkdir(parents=True)
    (home / ".cursor" / "mcp.json").write_text(json.dumps({"mcpServers": {"aws": {"env": {"AWS_ACCESS_KEY_ID": KEY_ID, "AWS_SECRET_ACCESS_KEY": SECRET}}}}))
    backend = HallucinatingBackend()
    board = _scan_with(backend, tmp_path / "out", ReconPaths(home=home, cwd=tmp_path, env={"AWS_SECRET_ACCESS_KEY": SECRET}))
    assert any(f.kind == "local_credential" and f.principal == user_arn("ci-admin") for f in board.verified)
    sent = "\n".join(p for _, p in backend.prompts)
    assert sent and SECRET not in sent and KEY_ID not in sent


def test_backend_failure_falls_back_to_deterministic_output(tmp_path):
    class Broken:
        name = "broken"

        def complete_json(self, **kw):
            raise LLMError("offline")

    board = _scan_with(Broken(), tmp_path)
    assert board.report["executive_summary"].startswith("Agent Radius found")
    assert len(board.report["llm"]["errors"]) == 4
