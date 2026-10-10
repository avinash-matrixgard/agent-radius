"""Small builders for in-memory snapshots."""

from __future__ import annotations

from typing import Any

from agent_radius.snapshot.fixture import snapshot_from_dict
from agent_radius.snapshot.model import Snapshot

ACCT = "111122223333"
OTHER = "999988887777"
R = "us-east-1"
ADMIN = "arn:aws:iam::aws:policy/AdministratorAccess"


def doc(*stmts: dict[str, Any]) -> dict[str, Any]:
    return {"Version": "2012-10-17", "Statement": list(stmts)}


def allow(action: Any, resource: Any = "*", **kw: Any) -> dict[str, Any]:
    st = {"Effect": "Allow", "Action": action, "Resource": resource}
    st.update(kw)
    return st


def deny(action: Any, resource: Any = "*", **kw: Any) -> dict[str, Any]:
    st = {"Effect": "Deny", "Action": action, "Resource": resource}
    st.update(kw)
    return st


def managed(arn: str, d: dict[str, Any]) -> dict[str, Any]:
    return {
        "PolicyName": arn.rsplit("/", 1)[-1],
        "Arn": arn,
        "DefaultVersionId": "v1",
        "PolicyVersionList": [{"Document": d, "VersionId": "v1", "IsDefaultVersion": True}],
    }


def role(name: str, attached=(), inline=None, boundary=None) -> dict[str, Any]:
    r: dict[str, Any] = {
        "RoleName": name,
        "Arn": f"arn:aws:iam::{ACCT}:role/{name}",
        "RolePolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()],
        "AttachedManagedPolicies": [{"PolicyArn": a} for a in attached],
    }
    if boundary:
        r["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    return r


def user(name: str, attached=(), inline=None, groups=(), boundary=None) -> dict[str, Any]:
    u: dict[str, Any] = {
        "UserName": name,
        "Arn": f"arn:aws:iam::{ACCT}:user/{name}",
        "UserPolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()],
        "GroupList": list(groups),
        "AttachedManagedPolicies": [{"PolicyArn": a} for a in attached],
    }
    if boundary:
        u["PermissionsBoundary"] = {"PermissionsBoundaryArn": boundary}
    return u


def group(name: str, attached=(), inline=None) -> dict[str, Any]:
    return {
        "GroupName": name,
        "Arn": f"arn:aws:iam::{ACCT}:group/{name}",
        "GroupPolicyList": [{"PolicyName": k, "PolicyDocument": v} for k, v in (inline or {}).items()],
        "AttachedManagedPolicies": [{"PolicyArn": a} for a in attached],
    }


def role_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCT}:role/{name}"


def user_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCT}:user/{name}"


def rds_arn(name: str) -> str:
    return f"arn:aws:rds:{R}:{ACCT}:db:{name}"


def table_arn(name: str) -> str:
    return f"arn:aws:dynamodb:{R}:{ACCT}:table/{name}"


def kms_arn(kid: str) -> str:
    return f"arn:aws:kms:{R}:{ACCT}:key/{kid}"


def make(
    users=(),
    roles=(),
    groups=(),
    policies=(),
    resources: dict[str, Any] | None = None,
    org: dict[str, Any] | None = None,
    creds=(),
    agent_principals=(),
    **extra: Any,
) -> Snapshot:
    data = {
        "schema_version": 1,
        "account_id": ACCT,
        "regions": [R],
        "iam": {
            "UserDetailList": list(users),
            "GroupDetailList": list(groups),
            "RoleDetailList": list(roles),
            "Policies": list(policies),
        },
        "organization": org,
        "resources": resources or {},
        "local_credentials": list(creds),
        "agent_principals": list(agent_principals),
    }
    data.update(extra)
    return snapshot_from_dict(data, source="test-fixture.json")
