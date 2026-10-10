"""Load a Snapshot from a fixture JSON file (the offline mode)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_radius.snapshot.model import (
    IamData,
    LocalCredential,
    Organization,
    Resources,
    Snapshot,
    _build,
)

SUPPORTED_SCHEMA_VERSIONS = {1}


class FixtureError(ValueError):
    pass


def snapshot_from_dict(data: dict[str, Any], source: str = "<memory>") -> Snapshot:
    version = data.get("schema_version", 1)
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise FixtureError(f"unsupported schema_version {version}")
    account_id = str(data.get("account_id", ""))
    if not (account_id.isdigit() and len(account_id) == 12):
        raise FixtureError("account_id must be a 12 digit string")
    regions = list(data.get("regions") or [data.get("region") or "us-east-1"])
    creds = [_build(LocalCredential, c) for c in data.get("local_credentials") or []]
    gaps = list(data.get("coverage_gaps") or [])
    org = Organization.from_dict(data.get("organization"))
    if data.get("organization") is None:
        gaps.append(
            "Service control policies were not collected; results assume no SCP restricts this account."
        )
    return Snapshot(
        account_id=account_id,
        regions=regions,
        iam=IamData.from_aws(data.get("iam")),
        organization=org,
        resources=Resources.from_dict(data.get("resources")),
        local_credentials=creds,
        agent_principals=list(data.get("agent_principals") or []),
        profile_principals=dict(data.get("profile_principals") or {}),
        access_key_fingerprints=dict(data.get("access_key_fingerprints") or {}),
        source=source,
        coverage_gaps=gaps,
    )


def load_fixture(path: str | Path) -> Snapshot:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FixtureError(f"{p}: invalid JSON: {exc}") from exc
    # Bench scenario files wrap the snapshot under "snapshot".
    if "snapshot" in data and "account_id" not in data:
        data = data["snapshot"]
    return snapshot_from_dict(data, source=str(p))
