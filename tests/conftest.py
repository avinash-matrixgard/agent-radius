"""Test isolation: no test may read the real home directory, real AWS config
or real credentials, and no test may reach a real AWS endpoint."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_environment(tmp_path_factory, monkeypatch):
    home = tmp_path_factory.mktemp("fake-home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(home / "no-such-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(home / "no-such-aws-credentials"))
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "ANTHROPIC_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS"):
        monkeypatch.delenv(var, raising=False)
    yield
