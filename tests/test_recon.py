"""Recon finds credential presence and paths, never values."""

from __future__ import annotations

import json
from pathlib import Path

from agent_radius.agents.orchestrator import RunOptions, run_scan
from agent_radius.agents.recon_scan import ReconPaths, fingerprint_access_key_id, scan_local
from tests.helpers import ADMIN, allow, doc, make, rds_arn, role, role_arn, user, user_arn

# AWS's published documentation example keys; not real credentials.
KEY_ID = "AKIATESTFIXTUREXYZ12"
SECRET = "TestFixture/SecretNotReal/00000000000001"
KEY_ID_2 = "AKIATESTFIXTUREXYZ34"
SECRET_2 = "TestFixture/SecretNotReal/00000000000002"
TOKEN = "FwoGZXIvYXdzEXAMPLETOKEN" + "A" * 120
ALL_SECRETS = [KEY_ID, SECRET, KEY_ID_2, SECRET_2, TOKEN]


def _home(tmp_path: Path) -> ReconPaths:
    home = tmp_path / "home"
    proj = tmp_path / "project"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "config").write_text(
        "[default]\nregion = us-east-1\n\n[profile agent]\nrole_arn = arn:aws:iam::111122223333:role/agent\nsource_profile = default\n"
        "\n[profile sso-dev]\nsso_session = corp\nsso_account_id = 111122223333\n\n[sso-session corp]\nsso_start_url = https://example.awsapps.com/start\n"
    )
    (home / ".aws" / "credentials").write_text(
        f"[default]\naws_access_key_id = {KEY_ID_2}\naws_secret_access_key = {SECRET_2}\naws_session_token = {TOKEN}\n"
    )
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(json.dumps({
        "mcpServers": {"aws": {"command": "uvx", "args": ["awslabs.aws-api-mcp-server"],
                               "env": {"AWS_ACCESS_KEY_ID": KEY_ID, "AWS_SECRET_ACCESS_KEY": SECRET}}}
    }))
    claude_desktop = home / "Library" / "Application Support" / "Claude"
    claude_desktop.mkdir(parents=True)
    (claude_desktop / "claude_desktop_config.json").write_text(json.dumps({
        "mcpServers": {"aws-prod": {"command": "npx", "args": ["aws-mcp", "--profile", "prod-admin"]}}
    }))
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(json.dumps({"env": {"AWS_PROFILE": "agent", "OTHER": "x"}}))
    (home / ".config" / "gcloud").mkdir(parents=True)
    (home / ".config" / "gcloud" / "application_default_credentials.json").write_text('{"type": "authorized_user", "refresh_token": "1//secret"}')
    proj.mkdir()
    (proj / ".vscode").mkdir()
    (proj / ".vscode" / "mcp.json").write_text(json.dumps({"servers": {"aws": {"command": "uvx", "args": [f"--key={KEY_ID}"]}}}))
    (proj / ".mcp.json").write_text("{ this is not json")
    env = {"AWS_ACCESS_KEY_ID": KEY_ID, "AWS_SECRET_ACCESS_KEY": SECRET, "AWS_PROFILE": "agent", "PATH": "/usr/bin"}
    return ReconPaths(home=home, cwd=proj, env=env)


def test_scan_finds_every_source_type(tmp_path):
    result = scan_local(_home(tmp_path))
    by_type: dict[str, list] = {}
    for c in result.credentials:
        by_type.setdefault(c.source_type, []).append(c)
    assert {"aws_profile", "mcp_config", "agent_config", "gcloud_adc", "env_var"} <= set(by_type)
    agent = next(c for c in by_type["aws_profile"] if c.profile_name == "agent")
    assert agent.principal_arn == "arn:aws:iam::111122223333:role/agent" and agent.mapped_via == "role_arn"
    default_creds = next(c for c in by_type["aws_profile"] if c.path.endswith("credentials"))
    assert default_creds.has_static_keys and "aws_secret_access_key" in default_creds.key_names
    cursor = next(c for c in by_type["mcp_config"] if ".cursor" in c.path)
    assert cursor.has_static_keys and cursor.key_names == ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    desktop = next(c for c in by_type["mcp_config"] if "claude_desktop" in c.path)
    assert desktop.profile_name == "prod-admin"
    vscode = next(c for c in by_type["mcp_config"] if ".vscode" in c.path)
    assert vscode.has_static_keys and "access key ID in args" in vscode.key_names
    assert by_type["agent_config"][0].profile_name == "agent"
    assert any(".mcp.json" in e for e in result.errors)  # malformed file reported, not fatal
    # Paths are shown relative to home, never absolute with the user name.
    assert all(not c.path.startswith(str(tmp_path)) for c in result.credentials)


def test_scan_records_contain_no_secret_values(tmp_path):
    result = scan_local(_home(tmp_path))
    blob = json.dumps([c.__dict__ for c in result.credentials]) + json.dumps(result.fingerprints)
    for secret in ALL_SECRETS + ["1//secret"]:
        assert secret not in blob
    assert fingerprint_access_key_id(KEY_ID) in result.fingerprints.values()


def test_full_scan_outputs_never_contain_secrets(tmp_path):
    paths = _home(tmp_path)
    snap = make(
        users=[user("ci-admin", attached=[ADMIN])],
        roles=[role("agent", inline={"Read": doc(allow("s3:Get*"))})],
        resources={"rds_instances": [{"identifier": "prod-db", "arn": rds_arn("prod-db")}]},
        access_key_fingerprints={fingerprint_access_key_id(KEY_ID): user_arn("ci-admin")},
        profile_principals={"prod-admin": user_arn("ci-admin")},
    )
    out = tmp_path / "out"
    board = run_scan(snap, RunOptions(out_dir=out, recon_paths=paths, terraform_bin=None))
    creds = {f.data["path"]: f for f in board.verified if f.kind == "local_credential"}
    assert creds["~/.cursor/mcp.json"].principal == user_arn("ci-admin")
    assert creds["~/.cursor/mcp.json"].data["mapped_via"] == "key_fingerprint"
    assert creds["~/.cursor/mcp.json"].severity == "high"
    assert role_arn("agent") in board.agent_principals and user_arn("ci-admin") in board.agent_principals
    written = "\n".join(p.read_text(errors="replace") for p in out.rglob("*") if p.is_file())
    assert written
    report_blob = json.dumps(board.report)
    for secret in ALL_SECRETS + ["1//secret"]:
        assert secret not in written
        assert secret not in report_blob


def test_profile_mapper_is_used_for_profiles(tmp_path):
    paths = _home(tmp_path)
    seen = []

    def mapper(profile):
        seen.append(profile)
        return role_arn("agent") if profile == "prod-admin" else None

    snap = make(roles=[role("agent")])
    board = run_scan(snap, RunOptions(out_dir=None, recon_paths=paths, profile_mapper=mapper, terraform_bin=None))
    assert "prod-admin" in seen
    desktop = next(f for f in board.verified if f.kind == "local_credential" and "claude_desktop" in f.data["path"])
    assert desktop.principal == role_arn("agent") and desktop.data["mapped_via"] == "sts"


def test_fixture_mode_does_not_touch_the_filesystem(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("fixture mode must not scan local files")

    monkeypatch.setattr("agent_radius.agents.recon.scan_local", boom)
    snap = make(roles=[role("agent")], local_credentials=[{
        "id": "cred:aws_profile:~/.aws/config#agent", "source_type": "aws_profile", "path": "~/.aws/config",
        "profile_name": "agent", "principal_arn": role_arn("agent")}])
    board = run_scan(snap, RunOptions(out_dir=None, terraform_bin=None))
    assert board.agent_principals == [role_arn("agent")]


def test_scanning_identity_is_only_a_fallback():
    snap = make(roles=[role("agent"), role("auditor")])
    board = run_scan(snap, RunOptions(out_dir=None, terraform_bin=None, fallback_principals=[role_arn("auditor")]))
    assert board.agent_principals == [role_arn("auditor")]
    snap2 = make(roles=[role("agent"), role("auditor")], agent_principals=[role_arn("agent")])
    board2 = run_scan(snap2, RunOptions(out_dir=None, terraform_bin=None, fallback_principals=[role_arn("auditor")]))
    assert board2.agent_principals == [role_arn("agent")]
