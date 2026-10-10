"""The bundled benchmark: at least 14 scenarios, all passing, zero hallucinations."""

from __future__ import annotations

import json

from agent_radius.bench.runner import run_bench, scenarios_dir

REQUIRED = {
    "admin-agent-prod-rds-same-account",
    "readonly-agent-scoped",
    "cross-account-vault-lock",
    "tfstate-unversioned",
    "boundary-excludes-deletes",
    "scp-denies-rds-delete",
    "kms-schedule-key-deletion",
    "notaction-trap",
    "mfa-conditioned-delete",
    "dynamodb-pitr-off",
    "s3-object-lock-compliance",
    "mcp-config-embedded-keys",
    "bucket-policy-denies-deletebucket",
    "dev-only-deletes",
}


def test_scenarios_have_fixture_and_truth():
    names = {p.name for p in scenarios_dir().iterdir() if p.is_dir()}
    assert REQUIRED <= names and len(names) >= 14
    for name in names:
        truth = json.loads((scenarios_dir() / name / "truth.json").read_text())
        assert truth["expect"] or truth["must_not"]


def test_bench_passes(tmp_path):
    payload = run_bench(results_path=tmp_path / "results.json")
    failing = [s for s in payload["scenarios"] if not s["passed"]]
    assert not failing, failing
    s = payload["summary"]
    assert s["precision"] == 1.0 and s["recall"] == 1.0 and s["hallucinations"] == 0
