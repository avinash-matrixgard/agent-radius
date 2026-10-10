"""The read-only gate: every AWS API call Agent Radius makes goes through here.

Three independent checks, all enforced in code BEFORE a request is signed:

1. Allowlist (primary). An operation must appear, by exact service and
   operation name, in ``READ_ONLY_OPERATIONS``. There are no patterns in the
   allowlist, so a new AWS operation can never slip in by matching ``Get*``.
2. Mutation verbs. Even an allowlisted name is refused if it starts with a
   verb that changes state (Delete, Put, Create, Update, Modify, Schedule,
   Terminate, Assume, ...). This guards against a bad edit to the allowlist.
3. Secret readers. Read-shaped operations that return secret material
   (GetSecretValue, GetParameter, Decrypt, GetPasswordData, GetObject, ...)
   are refused outright. Agent Radius never needs data plane reads.

The checks run twice: once when the caller looks up a method on the wrapped
client (``ReadOnlyClient.__getattr__``) and again inside botocore's
``before-call`` event, so even code that reached the raw client could not
send a mutating request.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any


class ReadOnlyViolation(RuntimeError):
    """Raised when anything tries to call a non-allowlisted AWS operation."""


# Exact operation names, keyed by botocore service name. Keep this list
# minimal: only what the live collector and recon actually call, plus a few
# documented read operations useful for future collectors.
READ_ONLY_OPERATIONS: dict[str, frozenset[str]] = {
    "sts": frozenset({"GetCallerIdentity"}),
    "iam": frozenset(
        {
            "GetAccountAuthorizationDetails",
            "ListAccessKeys",
            "ListUsers",
            "ListRoles",
            "GetPolicy",
            "GetPolicyVersion",
            "SimulatePrincipalPolicy",
        }
    ),
    "organizations": frozenset(
        {
            "DescribeOrganization",
            "ListRoots",
            "ListParents",
            "ListPoliciesForTarget",
            "DescribePolicy",
        }
    ),
    "s3": frozenset(
        {
            "ListBuckets",
            "GetBucketLocation",
            "GetBucketVersioning",
            "GetObjectLockConfiguration",
            "GetBucketPolicy",
            "GetBucketReplication",
            "GetBucketTagging",
            "GetBucketEncryption",
        }
    ),
    "rds": frozenset(
        {
            "DescribeDBInstances",
            "DescribeDBClusters",
            "DescribeDBSnapshots",
            "DescribeDBClusterSnapshots",
        }
    ),
    "dynamodb": frozenset(
        {
            "ListTables",
            "DescribeTable",
            "DescribeContinuousBackups",
            "ListBackups",
            "ListTagsOfResource",
        }
    ),
    "ec2": frozenset({"DescribeVolumes", "DescribeSnapshots"}),
    "kms": frozenset({"ListKeys", "DescribeKey", "GetKeyPolicy", "ListResourceTags"}),
    "backup": frozenset(
        {
            "ListBackupVaults",
            "GetBackupVaultAccessPolicy",
            "ListRecoveryPointsByBackupVault",
            "ListCopyJobs",
        }
    ),
}

# Verbs that change state. Matched against the start of the operation name.
MUTATING_VERB_RE = re.compile(
    r"^(Abort|Accept|Activate|Add|Apply|Assign|Associate|Assume|Attach|Authorize|"
    r"BatchDelete|BatchWrite|BatchPut|BatchUpdate|Bypass|Cancel|Change|Complete|Copy|"
    r"Create|Deactivate|Decline|Decrypt|Delete|Deregister|Detach|Disable|Disassociate|"
    r"Enable|Encrypt|Execute|Export|Failover|Generate|Import|Initiate|Invite|Invoke|"
    r"Leave|Lock|Merge|Modify|Move|Promote|Publish|Purge|Put|Reboot|Register|Reject|"
    r"Release|Remove|Replace|Reset|Restore|Retire|Revoke|Rotate|Run|Schedule|Send|Set|"
    r"Sign|Start|Stop|Swap|Tag|Terminate|Transfer|Unlock|Untag|Update|Upgrade|Upload)"
)

# Read-shaped operations that would return secret material or data contents.
SECRET_READ_OPERATIONS: frozenset[str] = frozenset(
    {
        "GetSecretValue",
        "BatchGetSecretValue",
        "GetParameter",
        "GetParameters",
        "GetParametersByPath",
        "GetPasswordData",
        "GetObject",
        "GetObjectTorrent",
        "SelectObjectContent",
        "GetSessionToken",
        "GetFederationToken",
        "GetAccessKeyInfo",
        "GetCredentialsForIdentity",
        "GetAuthorizationToken",
        "GetLoginProfile",
        "GetDataKey",
        "GetItem",
        "Query",
        "Scan",
        "ExportTableToPointInTime",
    }
)


def check_operation(service: str, operation: str) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for ``service:operation``.

    ``service`` is the botocore service name (``s3``, ``iam``, ``sts``...),
    ``operation`` the API operation name (``GetBucketPolicy``).
    """
    if operation in SECRET_READ_OPERATIONS:
        return False, f"{service}:{operation} returns secret material or data contents"
    if MUTATING_VERB_RE.match(operation):
        return False, f"{service}:{operation} starts with a state-changing verb"
    allowed = READ_ONLY_OPERATIONS.get(service, frozenset())
    if operation not in allowed:
        return False, f"{service}:{operation} is not on the read-only allowlist"
    return True, "allowlisted read-only operation"


def all_allowlisted_operations() -> list[str]:
    """Every allowlisted operation as ``service:Operation``, sorted."""
    return sorted(f"{svc}:{op}" for svc, ops in READ_ONLY_OPERATIONS.items() for op in ops)


@dataclass
class CallRecord:
    service: str
    operation: str
    region: str | None
    allowed: bool
    reason: str


@dataclass
class CallLog:
    """Thread-safe audit of every operation the gate saw."""

    records: list[CallRecord] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def add(self, record: CallRecord) -> None:
        with self._lock:
            self.records.append(record)

    def operations(self) -> list[str]:
        with self._lock:
            return sorted({f"{r.service}:{r.operation}" for r in self.records if r.allowed})

    def refusals(self) -> list[CallRecord]:
        with self._lock:
            return [r for r in self.records if not r.allowed]


# Attributes of a botocore client that do not send requests.
_SAFE_ATTRIBUTES = frozenset({"meta", "exceptions", "can_paginate"})


class ReadOnlyClient:
    """Wraps a botocore client and refuses every non-allowlisted operation."""

    def __init__(self, client: Any, log: CallLog | None = None) -> None:
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_log", log or CallLog())
        service = client.meta.service_model.service_name
        object.__setattr__(self, "_service", service)
        object.__setattr__(self, "_region", getattr(client.meta, "region_name", None))
        # Second line of defence: botocore fires before-call for every API
        # request, whichever object initiated it.
        client.meta.events.register("before-call", self._before_call)

    # botocore passes model=OperationModel plus other kwargs.
    def _before_call(self, model: Any = None, **_: Any) -> None:
        operation = getattr(model, "name", "<unknown>")
        allowed, reason = check_operation(self._service, operation)
        # This hook sees every request that is about to be sent, including
        # paginator pages, so it is the authoritative audit point.
        self._log.add(CallRecord(self._service, operation, self._region, allowed, reason))
        if not allowed:
            raise ReadOnlyViolation(f"refused before sending: {reason}")

    def _check(self, operation: str) -> None:
        allowed, reason = check_operation(self._service, operation)
        if not allowed:
            self._log.add(CallRecord(self._service, operation, self._region, False, reason))
            raise ReadOnlyViolation(reason)

    def __getattr__(self, name: str) -> Any:
        client = self._client
        if name in _SAFE_ATTRIBUTES:
            return getattr(client, name)
        if name == "get_paginator":
            return self._get_paginator
        mapping: dict[str, str] = client.meta.method_to_api_mapping
        if name in mapping:
            operation = mapping[name]
            # Validate at lookup time so a refused method is never even returned.
            allowed, reason = check_operation(self._service, operation)
            if not allowed:
                self._log.add(CallRecord(self._service, operation, self._region, False, reason))
                raise ReadOnlyViolation(reason)
            method = getattr(client, name)

            def guarded(*args: Any, **kwargs: Any) -> Any:
                self._check(operation)
                return method(*args, **kwargs)

            return guarded
        raise ReadOnlyViolation(
            f"attribute {name!r} of the {self._service} client is not exposed by the read-only gate"
        )

    def __setattr__(self, name: str, value: Any) -> None:  # pragma: no cover - defensive
        raise ReadOnlyViolation("the read-only client is immutable")

    def _get_paginator(self, name: str) -> Any:
        mapping: dict[str, str] = self._client.meta.method_to_api_mapping
        operation = mapping.get(name, name)
        allowed, reason = check_operation(self._service, operation)
        if not allowed:
            self._log.add(CallRecord(self._service, operation, self._region, False, reason))
            raise ReadOnlyViolation(reason)
        return self._client.get_paginator(name)


class ReadOnlyGate:
    """Factory for read-only clients bound to one boto3 session."""

    def __init__(self, session: Any, log: CallLog | None = None) -> None:
        self._session = session
        self.log = log or CallLog()

    def client(self, service: str, region_name: str | None = None) -> ReadOnlyClient:
        if service not in READ_ONLY_OPERATIONS:
            raise ReadOnlyViolation(f"service {service!r} has no read-only allowlist")
        raw = self._session.client(service, region_name=region_name)
        return ReadOnlyClient(raw, self.log)


def planned_operations(ops: Iterable[str]) -> list[str]:
    """Validate a declared list of ``service:Operation`` strings up front."""
    out = []
    for item in ops:
        service, _, operation = item.partition(":")
        allowed, reason = check_operation(service, operation)
        if not allowed:
            raise ReadOnlyViolation(f"declared operation refused: {reason}")
        out.append(item)
    return out


SessionFactory = Callable[[str | None], Any]
