"""CLI smoke tests (offline only)."""

from __future__ import annotations

import json

import pytest

from agent_radius.bench.runner import scenarios_dir
from agent_radius.cli import main

FIXTURE = scenarios_dir() / "admin-agent-prod-rds-same-account" / "fixture.json"


def test_scan_fixture_writes_reports(tmp_path, capsys):
    assert main(["scan", "--fixture", str(FIXTURE), "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "WHAT YOUR AGENT COULD DELETE IN 9 SECONDS" in out
    for name in ("report.md", "report.json", "report.html", "guardrails/deny_destructive.tf", "guardrails/README.md"):
        assert (tmp_path / name).is_file(), name
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["headline"] == "What your agent could delete in 9 seconds"
    assert report["headline_items"][0]["irreversibility"] == 3
    assert all(item["evidence_ids"] for item in report["headline_items"])
    assert report["llm"]["backend"] == "none"
    assert report["verification"]["terraform_validate"]["status"] in ("skipped", "passed", "failed", "error")


def test_fail_on_returns_nonzero(tmp_path):
    assert main(["scan", "--fixture", str(FIXTURE), "--out", str(tmp_path), "--fail-on", "critical", "--no-terraform"]) == 3


def test_demo(tmp_path, capsys):
    assert main(["demo", "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "no AWS calls" in out and "rds:DeleteDBInstance" in out


def test_catalog(capsys):
    assert main(["catalog"]) == 0
    assert "kms:ScheduleKeyDeletion" in capsys.readouterr().out


def test_scan_requires_a_source():
    with pytest.raises(SystemExit):
        main(["scan"])
    with pytest.raises(SystemExit):
        main(["scan", "--fixture", str(FIXTURE), "--llm", "gpt"])


def test_bench_command(tmp_path, capsys):
    results = tmp_path / "results.json"
    assert main(["bench", "--results", str(results)]) == 0
    out = capsys.readouterr().out
    assert "precision 1.000" in out and "hallucinations 0" in out
    assert json.loads(results.read_text())["summary"]["llm_backend"] == "none"


def test_live_mode_against_moto(tmp_path, monkeypatch, capsys):
    """Exercise the --profile path end to end against moto, from a tmp cwd and tmp home."""
    import boto3
    from moto import mock_aws

    cfg = tmp_path / "aws-config"
    cfg.write_text("[profile scanner]\nregion = us-east-1\naws_access_key_id = testing\naws_secret_access_key = testing\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    monkeypatch.chdir(tmp_path)
    with mock_aws():
        boto3.client("s3", region_name="us-east-1").create_bucket(Bucket="acme-tfstate-prod")
        rc = main(["scan", "--profile", "scanner", "--region", "us-east-1", "--out", str(tmp_path / "out"), "--no-terraform"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "LIVE MODE (read-only)" in out and "iam:GetAccountAuthorizationDetails" in out and "sts:AssumeRole" in out
    snapshot = json.loads((tmp_path / "out" / "snapshot.json").read_text())
    assert snapshot["resources"]["s3_buckets"][0]["name"] == "acme-tfstate-prod"
    assert (tmp_path / "out" / "report.json").is_file()
