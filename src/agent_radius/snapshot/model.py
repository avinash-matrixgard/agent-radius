"""Snapshot dataclasses.

IAM data keeps the exact shape of ``aws iam get-account-authorization-details``
(``UserDetailList``, ``GroupDetailList``, ``RoleDetailList``, ``Policies``) so a
real export can be dropped into a fixture unchanged. Resource records use
snake_case keys that mirror the dataclass fields one to one.
"""

from __future__ import annotations

import copy
import json
import re
import urllib.parse
from dataclasses import asdict, dataclass, field, fields
from typing import Any

# --------------------------------------------------------------------------
# Environment classification (prod first in every ranking)
# --------------------------------------------------------------------------

_PROD_RE = re.compile(r"(?:^|[^a-z0-9])(prod|production|prd|live)(?:[^a-z0-9]|$)", re.I)
_NONPROD_RE = re.compile(
    r"(?:^|[^a-z0-9])(dev|development|test|testing|staging|stage|stg|sandbox|qa|demo|tmp|scratch)"
    r"(?:[^a-z0-9]|$)",
    re.I,
)
_ENV_TAG_KEYS = {"env", "environment", "stage", "tier", "app-env", "app_env"}


def classify_env(name: str, tags: dict[str, str] | None = None) -> str:
    """Return ``prod``, ``nonprod`` or ``unknown`` from tags first, then name."""
    for key, value in (tags or {}).items():
        if key.lower() in _ENV_TAG_KEYS:
            if _PROD_RE.search(f" {value} "):
                return "prod"
            if _NONPROD_RE.search(f" {value} "):
                return "nonprod"
    if _PROD_RE.search(name or ""):
        return "prod"
    if _NONPROD_RE.search(name or ""):
        return "nonprod"
    return "unknown"


def load_policy_document(doc: Any) -> dict[str, Any] | None:
    """Accept a dict, a JSON string, or a URL-encoded JSON string."""
    if doc is None:
        return None
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        text = doc.strip()
        if not text:
            return None
        if not text.startswith("{"):
            text = urllib.parse.unquote(text)
        return json.loads(text)
    raise TypeError(f"unsupported policy document type: {type(doc).__name__}")


def _tags_from_list(tags: Any) -> dict[str, str]:
    if not tags:
        return {}
    if isinstance(tags, dict):
        return {str(k): str(v) for k, v in tags.items()}
    out: dict[str, str] = {}
    for item in tags:
        key = item.get("Key", item.get("key"))
        value = item.get("Value", item.get("value", ""))
        if key is not None:
            out[str(key)] = str(value)
    return out


def _build(cls: type, data: dict[str, Any]) -> Any:
    """Instantiate a flat dataclass from a dict, ignoring unknown keys."""
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in data.items() if k in names})


# --------------------------------------------------------------------------
# IAM
# --------------------------------------------------------------------------


@dataclass
class InlinePolicy:
    name: str
    document: dict[str, Any]


@dataclass
class ManagedPolicy:
    arn: str
    name: str
    document: dict[str, Any] | None
    default_version_id: str | None = None


@dataclass
class Principal:
    arn: str
    name: str
    kind: str  # "user" | "role"
    inline_policies: list[InlinePolicy] = field(default_factory=list)
    attached_policy_arns: list[str] = field(default_factory=list)
    group_names: list[str] = field(default_factory=list)
    permissions_boundary_arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)
    assume_role_policy: dict[str, Any] | None = None


@dataclass
class Group:
    arn: str
    name: str
    inline_policies: list[InlinePolicy] = field(default_factory=list)
    attached_policy_arns: list[str] = field(default_factory=list)


# The one AWS managed policy whose document is short, stable and safe to
# embed. Every other AWS managed policy must be present in the snapshot.
BUILTIN_MANAGED_POLICIES: dict[str, dict[str, Any]] = {
    "arn:aws:iam::aws:policy/AdministratorAccess": {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
}


def _inline_list(items: Any) -> list[InlinePolicy]:
    out = []
    for item in items or []:
        out.append(InlinePolicy(item["PolicyName"], load_policy_document(item["PolicyDocument"]) or {}))
    return out


def _boundary(item: dict[str, Any]) -> str | None:
    pb = item.get("PermissionsBoundary") or {}
    return pb.get("PermissionsBoundaryArn")


@dataclass
class IamData:
    users: dict[str, Principal]
    roles: dict[str, Principal]
    groups: dict[str, Group]
    policies: dict[str, ManagedPolicy]
    raw: dict[str, Any]

    @classmethod
    def from_aws(cls, raw: dict[str, Any] | None) -> IamData:
        raw = raw or {}
        policies: dict[str, ManagedPolicy] = {}
        for item in raw.get("Policies", []) or []:
            default_id = item.get("DefaultVersionId")
            document = None
            for version in item.get("PolicyVersionList", []) or []:
                if version.get("IsDefaultVersion") or version.get("VersionId") == default_id:
                    document = load_policy_document(version.get("Document"))
                    break
            policies[item["Arn"]] = ManagedPolicy(
                arn=item["Arn"],
                name=item.get("PolicyName", item["Arn"].rsplit("/", 1)[-1]),
                document=document,
                default_version_id=default_id,
            )
        groups: dict[str, Group] = {}
        for item in raw.get("GroupDetailList", []) or []:
            groups[item["GroupName"]] = Group(
                arn=item["Arn"],
                name=item["GroupName"],
                inline_policies=_inline_list(item.get("GroupPolicyList")),
                attached_policy_arns=[p["PolicyArn"] for p in item.get("AttachedManagedPolicies", []) or []],
            )
        users: dict[str, Principal] = {}
        for item in raw.get("UserDetailList", []) or []:
            users[item["Arn"]] = Principal(
                arn=item["Arn"],
                name=item["UserName"],
                kind="user",
                inline_policies=_inline_list(item.get("UserPolicyList")),
                attached_policy_arns=[p["PolicyArn"] for p in item.get("AttachedManagedPolicies", []) or []],
                group_names=list(item.get("GroupList", []) or []),
                permissions_boundary_arn=_boundary(item),
                tags=_tags_from_list(item.get("Tags")),
            )
        roles: dict[str, Principal] = {}
        for item in raw.get("RoleDetailList", []) or []:
            roles[item["Arn"]] = Principal(
                arn=item["Arn"],
                name=item["RoleName"],
                kind="role",
                inline_policies=_inline_list(item.get("RolePolicyList")),
                attached_policy_arns=[p["PolicyArn"] for p in item.get("AttachedManagedPolicies", []) or []],
                permissions_boundary_arn=_boundary(item),
                tags=_tags_from_list(item.get("Tags")),
                assume_role_policy=load_policy_document(item.get("AssumeRolePolicyDocument")),
            )
        return cls(users=users, roles=roles, groups=groups, policies=policies, raw=raw)

    def managed_document(self, arn: str) -> dict[str, Any] | None:
        policy = self.policies.get(arn)
        if policy is not None and policy.document is not None:
            return policy.document
        return BUILTIN_MANAGED_POLICIES.get(arn)

    def principal(self, arn: str) -> Principal | None:
        if arn in self.users:
            return self.users[arn]
        if arn in self.roles:
            return self.roles[arn]
        # STS assumed-role session ARN -> the underlying role.
        match = re.match(r"^arn:(aws[a-z-]*):sts::(\d{12}):assumed-role/([^/]+)/", arn)
        if match:
            name = match.group(3)
            for role in self.roles.values():
                if role.name == name:
                    return role
        return None

    def all_principals(self) -> list[Principal]:
        return list(self.users.values()) + list(self.roles.values())


# --------------------------------------------------------------------------
# Organizations
# --------------------------------------------------------------------------


@dataclass
class Scp:
    id: str
    name: str
    document: dict[str, Any]
    level: str = "account"


@dataclass
class Organization:
    management_account: bool = False
    scps: list[Scp] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Organization | None:
        if data is None:
            return None
        scps = [
            Scp(
                id=s["id"],
                name=s.get("name", s["id"]),
                document=load_policy_document(s["document"]) or {},
                level=s.get("level", "account"),
            )
            for s in data.get("scps", []) or []
        ]
        return cls(management_account=bool(data.get("management_account", False)), scps=scps)


# --------------------------------------------------------------------------
# Resources
# --------------------------------------------------------------------------


@dataclass
class ObjectLock:
    enabled: bool = False
    mode: str | None = None  # "COMPLIANCE" | "GOVERNANCE" | None
    days: int | None = None
    years: int | None = None


@dataclass
class ReplicationRule:
    destination_bucket_arn: str
    destination_account: str | None = None
    destination_region: str | None = None
    status: str = "Enabled"


@dataclass
class S3Bucket:
    name: str
    region: str = "us-east-1"
    versioning: str = "Disabled"  # Enabled | Suspended | Disabled
    mfa_delete: bool = False
    object_lock: ObjectLock = field(default_factory=ObjectLock)
    policy: dict[str, Any] | None = None
    replication: list[ReplicationRule] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)
    kms_key_arn: str | None = None

    @property
    def arn(self) -> str:
        return f"arn:aws:s3:::{self.name}"

    @property
    def objects_arn(self) -> str:
        return f"arn:aws:s3:::{self.name}/*"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> S3Bucket:
        data = dict(data)
        data["object_lock"] = _build(ObjectLock, data.get("object_lock") or {})
        data["replication"] = [_build(ReplicationRule, r) for r in data.get("replication") or []]
        data["policy"] = load_policy_document(data.get("policy"))
        data["tags"] = _tags_from_list(data.get("tags"))
        return _build(cls, data)


@dataclass
class RdsInstance:
    identifier: str
    arn: str
    engine: str = "postgres"
    deletion_protection: bool = False
    backup_retention_period: int = 0
    kms_key_arn: str | None = None
    cluster_identifier: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class RdsCluster:
    identifier: str
    arn: str
    engine: str = "aurora-postgresql"
    deletion_protection: bool = False
    backup_retention_period: int = 1
    kms_key_arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class RdsSnapshot:
    identifier: str
    arn: str
    source_identifier: str
    source_kind: str = "instance"  # "instance" | "cluster"
    snapshot_type: str = "manual"

    @property
    def account_id(self) -> str:
        return self.arn.split(":")[4]

    @property
    def region(self) -> str:
        return self.arn.split(":")[3]


@dataclass
class DynamoBackup:
    arn: str
    name: str = ""
    backup_type: str = "USER"


@dataclass
class DynamoTable:
    name: str
    arn: str
    deletion_protection: bool = False
    pitr_enabled: bool = False
    backups: list[DynamoBackup] = field(default_factory=list)
    kms_key_arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def backup_wildcard_arn(self) -> str:
        return f"{self.arn}/backup/*"

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DynamoTable:
        data = dict(data)
        data["backups"] = [_build(DynamoBackup, b) for b in data.get("backups") or []]
        data["tags"] = _tags_from_list(data.get("tags"))
        return _build(cls, data)


@dataclass
class EbsVolume:
    volume_id: str
    arn: str
    size_gb: int = 0
    kms_key_arn: str | None = None
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class EbsSnapshot:
    snapshot_id: str
    arn: str
    volume_id: str

    @property
    def account_id(self) -> str:
        return self.arn.split(":")[4]

    @property
    def region(self) -> str:
        return self.arn.split(":")[3]


@dataclass
class KmsKey:
    key_id: str
    arn: str
    policy: dict[str, Any] | None = None
    key_state: str = "Enabled"
    key_manager: str = "CUSTOMER"
    origin: str = "AWS_KMS"  # AWS_KMS | EXTERNAL | AWS_CLOUDHSM | EXTERNAL_KEY_STORE
    description: str = ""
    tags: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> KmsKey:
        data = dict(data)
        data["policy"] = load_policy_document(data.get("policy"))
        data["tags"] = _tags_from_list(data.get("tags"))
        return _build(cls, data)


@dataclass
class BackupVault:
    name: str
    arn: str
    access_policy: dict[str, Any] | None = None
    lock_mode: str | None = None  # "COMPLIANCE" | "GOVERNANCE" | None
    lock_immutable: bool = False  # compliance mode past its cooling-off date
    min_retention_days: int | None = None
    max_retention_days: int | None = None

    @property
    def account_id(self) -> str:
        return self.arn.split(":")[4]

    @property
    def region(self) -> str:
        return self.arn.split(":")[3]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BackupVault:
        data = dict(data)
        data["access_policy"] = load_policy_document(data.get("access_policy"))
        if data.get("lock_mode"):
            data["lock_mode"] = str(data["lock_mode"]).upper()
        return _build(cls, data)


@dataclass
class RecoveryPoint:
    arn: str
    vault_arn: str
    source_resource_arn: str
    resource_type: str = ""
    status: str = "COMPLETED"
    observed_via: str = "vault"  # "vault" | "copy_job" | "fixture"

    @property
    def account_id(self) -> str:
        return self.arn.split(":")[4]

    @property
    def region(self) -> str:
        return self.arn.split(":")[3]


@dataclass
class ResourceRef:
    """A pointer into the snapshot's resource index."""

    arn: str
    resource_type: str
    name: str
    obj: Any
    tags: dict[str, str]

    @property
    def env(self) -> str:
        return classify_env(self.name, self.tags)


@dataclass
class Resources:
    s3_buckets: list[S3Bucket] = field(default_factory=list)
    rds_instances: list[RdsInstance] = field(default_factory=list)
    rds_clusters: list[RdsCluster] = field(default_factory=list)
    rds_snapshots: list[RdsSnapshot] = field(default_factory=list)
    dynamodb_tables: list[DynamoTable] = field(default_factory=list)
    ebs_volumes: list[EbsVolume] = field(default_factory=list)
    ebs_snapshots: list[EbsSnapshot] = field(default_factory=list)
    kms_keys: list[KmsKey] = field(default_factory=list)
    backup_vaults: list[BackupVault] = field(default_factory=list)
    recovery_points: list[RecoveryPoint] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> Resources:
        data = data or {}

        def tagged(kind: type, items: Any) -> list[Any]:
            out = []
            for item in items or []:
                item = dict(item)
                if "tags" in item:
                    item["tags"] = _tags_from_list(item["tags"])
                out.append(_build(kind, item))
            return out

        return cls(
            s3_buckets=[S3Bucket.from_dict(b) for b in data.get("s3_buckets") or []],
            rds_instances=tagged(RdsInstance, data.get("rds_instances")),
            rds_clusters=tagged(RdsCluster, data.get("rds_clusters")),
            rds_snapshots=tagged(RdsSnapshot, data.get("rds_snapshots")),
            dynamodb_tables=[DynamoTable.from_dict(t) for t in data.get("dynamodb_tables") or []],
            ebs_volumes=tagged(EbsVolume, data.get("ebs_volumes")),
            ebs_snapshots=tagged(EbsSnapshot, data.get("ebs_snapshots")),
            kms_keys=[KmsKey.from_dict(k) for k in data.get("kms_keys") or []],
            backup_vaults=[BackupVault.from_dict(v) for v in data.get("backup_vaults") or []],
            recovery_points=tagged(RecoveryPoint, data.get("recovery_points")),
        )


# --------------------------------------------------------------------------
# Local credentials (what recon found; never secret values)
# --------------------------------------------------------------------------


@dataclass
class LocalCredential:
    id: str
    source_type: str  # aws_profile | env_var | mcp_config | gcloud_adc | agent_config
    path: str
    profile_name: str | None = None
    principal_arn: str | None = None
    has_static_keys: bool = False
    key_names: list[str] = field(default_factory=list)
    detail: str = ""
    mapped_via: str | None = None  # fixture | profile_map | key_fingerprint | role_arn | sts


# --------------------------------------------------------------------------
# Snapshot
# --------------------------------------------------------------------------


@dataclass
class Snapshot:
    account_id: str
    regions: list[str]
    iam: IamData
    organization: Organization | None = None
    resources: Resources = field(default_factory=Resources)
    local_credentials: list[LocalCredential] = field(default_factory=list)
    agent_principals: list[str] = field(default_factory=list)
    profile_principals: dict[str, str] = field(default_factory=dict)
    access_key_fingerprints: dict[str, str] = field(default_factory=dict)
    source: str = "<memory>"
    coverage_gaps: list[str] = field(default_factory=list)
    _index: dict[str, ResourceRef] | None = field(default=None, repr=False, compare=False)

    @property
    def region(self) -> str:
        return self.regions[0] if self.regions else "us-east-1"

    @property
    def root_arn(self) -> str:
        return f"arn:aws:iam::{self.account_id}:root"

    # ---- resource index -------------------------------------------------

    def resource_index(self) -> dict[str, ResourceRef]:
        if self._index is not None:
            return self._index
        idx: dict[str, ResourceRef] = {}
        r = self.resources
        for b in r.s3_buckets:
            idx[b.arn] = ResourceRef(b.arn, "s3_bucket", b.name, b, b.tags)
            idx[b.objects_arn] = ResourceRef(b.objects_arn, "s3_objects", b.name, b, b.tags)
        for i in r.rds_instances:
            idx[i.arn] = ResourceRef(i.arn, "rds_instance", i.identifier, i, i.tags)
        for c in r.rds_clusters:
            idx[c.arn] = ResourceRef(c.arn, "rds_cluster", c.identifier, c, c.tags)
        for s in r.rds_snapshots:
            kind = "rds_cluster_snapshot" if s.source_kind == "cluster" else "rds_snapshot"
            idx[s.arn] = ResourceRef(s.arn, kind, s.identifier, s, self._source_tags(s.source_identifier))
        for t in r.dynamodb_tables:
            idx[t.arn] = ResourceRef(t.arn, "dynamodb_table", t.name, t, t.tags)
            idx[t.backup_wildcard_arn] = ResourceRef(t.backup_wildcard_arn, "dynamodb_backup", t.name, t, t.tags)
            for bk in t.backups:
                idx[bk.arn] = ResourceRef(bk.arn, "dynamodb_backup", bk.name or t.name, bk, t.tags)
        for v in r.ebs_volumes:
            idx[v.arn] = ResourceRef(v.arn, "ebs_volume", v.volume_id, v, v.tags)
        for s in r.ebs_snapshots:
            idx[s.arn] = ResourceRef(s.arn, "ebs_snapshot", s.snapshot_id, s, self._volume_tags(s.volume_id))
        for k in r.kms_keys:
            idx[k.arn] = ResourceRef(k.arn, "kms_key", k.description or k.key_id, k, k.tags)
        for v in r.backup_vaults:
            idx[v.arn] = ResourceRef(v.arn, "backup_vault", v.name, v, {})
        for p in r.recovery_points:
            src = idx.get(p.source_resource_arn)
            idx[p.arn] = ResourceRef(p.arn, "recovery_point", p.arn.rsplit(":", 1)[-1], p, src.tags if src else {})
        for p in self.iam.roles.values():
            idx[p.arn] = ResourceRef(p.arn, "iam_role", p.name, p, p.tags)
        for p in self.iam.users.values():
            idx[p.arn] = ResourceRef(p.arn, "iam_user", p.name, p, p.tags)
        self._index = idx
        return idx

    def _source_tags(self, identifier: str) -> dict[str, str]:
        for i in self.resources.rds_instances:
            if i.identifier == identifier:
                return i.tags
        for c in self.resources.rds_clusters:
            if c.identifier == identifier:
                return c.tags
        return {}

    def _volume_tags(self, volume_id: str) -> dict[str, str]:
        for v in self.resources.ebs_volumes:
            if v.volume_id == volume_id:
                return v.tags
        return {}

    def resource(self, arn: str) -> ResourceRef | None:
        return self.resource_index().get(arn)

    def resources_of_type(self, resource_type: str) -> list[ResourceRef]:
        return [ref for ref in self.resource_index().values() if ref.resource_type == resource_type]

    def bucket_for_arn(self, arn: str) -> S3Bucket | None:
        if not arn.startswith("arn:aws:s3:::"):
            return None
        name = arn[len("arn:aws:s3:::") :].split("/", 1)[0]
        for b in self.resources.s3_buckets:
            if b.name == name:
                return b
        return None

    def kms_key(self, arn: str) -> KmsKey | None:
        for k in self.resources.kms_keys:
            if k.arn == arn:
                return k
        return None

    def vault_for_arn(self, arn: str) -> BackupVault | None:
        for v in self.resources.backup_vaults:
            if v.arn == arn:
                return v
        for p in self.resources.recovery_points:
            if p.arn == arn:
                for v in self.resources.backup_vaults:
                    if v.arn == p.vault_arn:
                        return v
        return None

    def principal_arns(self) -> set[str]:
        return set(self.iam.users) | set(self.iam.roles)

    # ---- mutation helpers for what-if analysis (always on a copy) --------

    def with_inline_policy(self, principal_arn: str, name: str, document: dict[str, Any]) -> Snapshot:
        clone = copy.deepcopy(self)
        clone._index = None
        principal = clone.iam.principal(principal_arn)
        if principal is None:
            raise KeyError(f"unknown principal {principal_arn}")
        principal.inline_policies.append(InlinePolicy(name, copy.deepcopy(document)))
        return clone

    # ---- serialisation --------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        def plain(obj: Any) -> Any:
            return asdict(obj)

        org = None
        if self.organization is not None:
            org = {
                "management_account": self.organization.management_account,
                "scps": [plain(s) for s in self.organization.scps],
            }
        res = self.resources
        return {
            "schema_version": 1,
            "account_id": self.account_id,
            "regions": list(self.regions),
            "iam": self.iam.raw,
            "organization": org,
            "resources": {
                "s3_buckets": [plain(b) for b in res.s3_buckets],
                "rds_instances": [plain(i) for i in res.rds_instances],
                "rds_clusters": [plain(c) for c in res.rds_clusters],
                "rds_snapshots": [plain(s) for s in res.rds_snapshots],
                "dynamodb_tables": [plain(t) for t in res.dynamodb_tables],
                "ebs_volumes": [plain(v) for v in res.ebs_volumes],
                "ebs_snapshots": [plain(s) for s in res.ebs_snapshots],
                "kms_keys": [plain(k) for k in res.kms_keys],
                "backup_vaults": [plain(v) for v in res.backup_vaults],
                "recovery_points": [plain(p) for p in res.recovery_points],
            },
            "local_credentials": [plain(c) for c in self.local_credentials],
            "agent_principals": list(self.agent_principals),
            "profile_principals": dict(self.profile_principals),
            "access_key_fingerprints": dict(self.access_key_fingerprints),
            "coverage_gaps": list(self.coverage_gaps),
        }
