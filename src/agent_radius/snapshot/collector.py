"""Live, read-only collector. Every call goes through the ReadOnlyGate.

``LIVE_OPERATIONS`` is the complete list of API operations this module can
call; the CLI prints it before a live scan, and a unit test asserts every
entry passes the gate.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Callable
from typing import Any

from agent_radius.agents.recon_scan import fingerprint_access_key_id
from agent_radius.security.readonly_gate import (
    CallLog,
    ReadOnlyGate,
    ReadOnlyViolation,
    planned_operations,
)
from agent_radius.snapshot.model import (
    BackupVault,
    DynamoBackup,
    DynamoTable,
    EbsSnapshot,
    EbsVolume,
    IamData,
    KmsKey,
    ObjectLock,
    Organization,
    RdsCluster,
    RdsInstance,
    RdsSnapshot,
    RecoveryPoint,
    ReplicationRule,
    Resources,
    S3Bucket,
    Scp,
    Snapshot,
    _tags_from_list,
    load_policy_document,
)

LIVE_OPERATIONS: list[str] = planned_operations(
    [
        "sts:GetCallerIdentity",
        "iam:GetAccountAuthorizationDetails",
        "iam:ListAccessKeys",
        "organizations:DescribeOrganization",
        "organizations:ListParents",
        "organizations:ListPoliciesForTarget",
        "organizations:DescribePolicy",
        "s3:ListBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketVersioning",
        "s3:GetObjectLockConfiguration",
        "s3:GetBucketPolicy",
        "s3:GetBucketReplication",
        "s3:GetBucketTagging",
        "s3:GetBucketEncryption",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "rds:DescribeDBSnapshots",
        "rds:DescribeDBClusterSnapshots",
        "dynamodb:ListTables",
        "dynamodb:DescribeTable",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:ListBackups",
        "dynamodb:ListTagsOfResource",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyPolicy",
        "kms:ListResourceTags",
        "backup:ListBackupVaults",
        "backup:GetBackupVaultAccessPolicy",
        "backup:ListRecoveryPointsByBackupVault",
        "backup:ListCopyJobs",
    ]
)


class _Gaps:
    def __init__(self) -> None:
        self.items: list[str] = []

    def attempt(self, label: str, fn: Callable[[], Any], default: Any = None, quiet_codes: tuple[str, ...] = ()) -> Any:
        try:
            return fn()
        except ReadOnlyViolation:
            raise
        except Exception as exc:  # noqa: BLE001 - every API failure becomes a recorded coverage gap
            code = _error_code(exc)
            if code in quiet_codes:
                return default
            self.items.append(f"{label}: {code or type(exc).__name__}")
            return default


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        return response.get("Error", {}).get("Code")
    return None


def _paginate(client: Any, method: str, key: str, **kwargs: Any) -> list[Any]:
    out: list[Any] = []
    if client.can_paginate(method):
        for page in client.get_paginator(method).paginate(**kwargs):
            out += page.get(key, [])
        return out
    return list(getattr(client, method)(**kwargs).get(key, []))


def _collect_iam(gate: ReadOnlyGate, gaps: _Gaps) -> tuple[dict[str, Any], dict[str, str]]:
    iam = gate.client("iam")
    merged: dict[str, list[Any]] = {"UserDetailList": [], "GroupDetailList": [], "RoleDetailList": [], "Policies": []}
    paginator = iam.get_paginator("get_account_authorization_details")
    for page in paginator.paginate(Filter=["User", "Role", "Group", "LocalManagedPolicy", "AWSManagedPolicy"]):
        for key in merged:
            merged[key] += page.get(key, [])
    # Policy documents come back as dicts from boto3; make them JSON safe.
    raw = json.loads(json.dumps(merged, default=str))
    fingerprints: dict[str, str] = {}
    for user in raw["UserDetailList"]:
        keys = gaps.attempt(
            f"iam:ListAccessKeys {user['UserName']}",
            lambda u=user: _paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=u["UserName"]),
            [],
        )
        for k in keys:
            # Hash the key ID immediately; the raw ID is never stored.
            fingerprints[fingerprint_access_key_id(k["AccessKeyId"])] = user["Arn"]
    return raw, fingerprints


def _collect_scps(gate: ReadOnlyGate, account_id: str, region: str, gaps: _Gaps) -> Organization | None:
    org = gate.client("organizations", region_name=region)
    desc = gaps.attempt("organizations:DescribeOrganization", lambda: org.describe_organization(), None, ("AWSOrganizationsNotInUseException",))
    if desc is None:
        return None
    management = desc["Organization"].get("MasterAccountId") == account_id
    targets = [("account", account_id)]
    child = account_id
    for _ in range(6):
        parents = gaps.attempt("organizations:ListParents", lambda c=child: org.list_parents(ChildId=c)["Parents"], [])
        if not parents:
            break
        parent = parents[0]
        targets.append(("root" if parent["Type"] == "ROOT" else f"ou:{parent['Id']}", parent["Id"]))
        if parent["Type"] == "ROOT":
            break
        child = parent["Id"]
    scps: list[Scp] = []
    for level, target in targets:
        policies = gaps.attempt(
            f"organizations:ListPoliciesForTarget {level}",
            lambda t=target: _paginate(org, "list_policies_for_target", "Policies", TargetId=t, Filter="SERVICE_CONTROL_POLICY"),
            None,
        )
        if policies is None:
            return None
        for p in policies:
            content = gaps.attempt(
                f"organizations:DescribePolicy {p['Id']}",
                lambda pid=p["Id"]: org.describe_policy(PolicyId=pid)["Policy"]["Content"],
                None,
            )
            if content is None:
                return None
            scps.append(Scp(id=p["Id"], name=p.get("Name", p["Id"]), document=load_policy_document(content) or {}, level=level))
    return Organization(management_account=management, scps=scps)


def _collect_s3(gate: ReadOnlyGate, region: str, gaps: _Gaps) -> list[S3Bucket]:
    s3 = gate.client("s3", region_name=region)
    buckets = gaps.attempt("s3:ListBuckets", lambda: s3.list_buckets()["Buckets"], [])
    out: list[S3Bucket] = []
    for b in buckets:
        name = b["Name"]
        loc = gaps.attempt(f"s3:GetBucketLocation {name}", lambda n=name: s3.get_bucket_location(Bucket=n).get("LocationConstraint"), None)
        bucket = S3Bucket(name=name, region=loc or "us-east-1")
        v = gaps.attempt(f"s3:GetBucketVersioning {name}", lambda n=name: s3.get_bucket_versioning(Bucket=n), {}) or {}
        bucket.versioning = v.get("Status") or "Disabled"
        bucket.mfa_delete = v.get("MFADelete") == "Enabled"
        lock = gaps.attempt(
            f"s3:GetObjectLockConfiguration {name}",
            lambda n=name: s3.get_object_lock_configuration(Bucket=n).get("ObjectLockConfiguration", {}),
            {},
            ("ObjectLockConfigurationNotFoundError",),
        ) or {}
        rule = (lock.get("Rule") or {}).get("DefaultRetention") or {}
        bucket.object_lock = ObjectLock(
            enabled=lock.get("ObjectLockEnabled") == "Enabled",
            mode=rule.get("Mode"),
            days=rule.get("Days"),
            years=rule.get("Years"),
        )
        policy = gaps.attempt(
            f"s3:GetBucketPolicy {name}", lambda n=name: s3.get_bucket_policy(Bucket=n).get("Policy"), None, ("NoSuchBucketPolicy",)
        )
        bucket.policy = load_policy_document(policy) if policy else None
        repl = gaps.attempt(
            f"s3:GetBucketReplication {name}",
            lambda n=name: s3.get_bucket_replication(Bucket=n).get("ReplicationConfiguration", {}),
            {},
            ("ReplicationConfigurationNotFoundError",),
        ) or {}
        for r in repl.get("Rules", []):
            dest = r.get("Destination", {})
            if dest.get("Bucket"):
                bucket.replication.append(
                    ReplicationRule(destination_bucket_arn=dest["Bucket"], destination_account=dest.get("Account"), status=r.get("Status", "Enabled"))
                )
        tags = gaps.attempt(f"s3:GetBucketTagging {name}", lambda n=name: s3.get_bucket_tagging(Bucket=n).get("TagSet", []), [], ("NoSuchTagSet",))
        bucket.tags = _tags_from_list(tags)
        enc = gaps.attempt(
            f"s3:GetBucketEncryption {name}",
            lambda n=name: s3.get_bucket_encryption(Bucket=n).get("ServerSideEncryptionConfiguration", {}),
            {},
            ("ServerSideEncryptionConfigurationNotFoundError",),
        ) or {}
        for r in enc.get("Rules", []):
            key = (r.get("ApplyServerSideEncryptionByDefault") or {}).get("KMSMasterKeyID")
            if key and key.startswith("arn:"):
                bucket.kms_key_arn = key
        out.append(bucket)
    return out


def _collect_region(gate: ReadOnlyGate, region: str, account_id: str, res: Resources, gaps: _Gaps, now: _dt.datetime) -> None:
    rds = gate.client("rds", region_name=region)
    for i in gaps.attempt(f"rds:DescribeDBInstances {region}", lambda: _paginate(rds, "describe_db_instances", "DBInstances"), []):
        res.rds_instances.append(
            RdsInstance(
                identifier=i["DBInstanceIdentifier"],
                arn=i["DBInstanceArn"],
                engine=i.get("Engine", ""),
                deletion_protection=bool(i.get("DeletionProtection")),
                backup_retention_period=int(i.get("BackupRetentionPeriod") or 0),
                kms_key_arn=i.get("KmsKeyId"),
                cluster_identifier=i.get("DBClusterIdentifier"),
                tags=_tags_from_list(i.get("TagList")),
            )
        )
    for c in gaps.attempt(f"rds:DescribeDBClusters {region}", lambda: _paginate(rds, "describe_db_clusters", "DBClusters"), []):
        res.rds_clusters.append(
            RdsCluster(
                identifier=c["DBClusterIdentifier"],
                arn=c["DBClusterArn"],
                engine=c.get("Engine", ""),
                deletion_protection=bool(c.get("DeletionProtection")),
                backup_retention_period=int(c.get("BackupRetentionPeriod") or 0),
                kms_key_arn=c.get("KmsKeyId"),
                tags=_tags_from_list(c.get("TagList")),
            )
        )
    for s in gaps.attempt(f"rds:DescribeDBSnapshots {region}", lambda: _paginate(rds, "describe_db_snapshots", "DBSnapshots"), []):
        res.rds_snapshots.append(
            RdsSnapshot(identifier=s["DBSnapshotIdentifier"], arn=s["DBSnapshotArn"], source_identifier=s.get("DBInstanceIdentifier", ""),
                        source_kind="instance", snapshot_type=s.get("SnapshotType", "manual"))
        )
    for s in gaps.attempt(f"rds:DescribeDBClusterSnapshots {region}", lambda: _paginate(rds, "describe_db_cluster_snapshots", "DBClusterSnapshots"), []):
        res.rds_snapshots.append(
            RdsSnapshot(identifier=s["DBClusterSnapshotIdentifier"], arn=s["DBClusterSnapshotArn"], source_identifier=s.get("DBClusterIdentifier", ""),
                        source_kind="cluster", snapshot_type=s.get("SnapshotType", "manual"))
        )

    ddb = gate.client("dynamodb", region_name=region)
    for name in gaps.attempt(f"dynamodb:ListTables {region}", lambda: _paginate(ddb, "list_tables", "TableNames"), []):
        desc = gaps.attempt(f"dynamodb:DescribeTable {name}", lambda n=name: ddb.describe_table(TableName=n)["Table"], None)
        if desc is None:
            continue
        cb = gaps.attempt(f"dynamodb:DescribeContinuousBackups {name}", lambda n=name: ddb.describe_continuous_backups(TableName=n), {}) or {}
        pitr = (cb.get("ContinuousBackupsDescription", {}).get("PointInTimeRecoveryDescription", {}) or {}).get("PointInTimeRecoveryStatus")
        backups = gaps.attempt(f"dynamodb:ListBackups {name}", lambda n=name: ddb.list_backups(TableName=n).get("BackupSummaries", []), []) or []
        tags = gaps.attempt(f"dynamodb:ListTagsOfResource {name}", lambda a=desc["TableArn"]: ddb.list_tags_of_resource(ResourceArn=a).get("Tags", []), []) or []
        res.dynamodb_tables.append(
            DynamoTable(
                name=name,
                arn=desc["TableArn"],
                deletion_protection=bool(desc.get("DeletionProtectionEnabled")),
                pitr_enabled=pitr == "ENABLED",
                backups=[DynamoBackup(arn=b["BackupArn"], name=b.get("BackupName", ""), backup_type=b.get("BackupType", "USER")) for b in backups],
                kms_key_arn=(desc.get("SSEDescription") or {}).get("KMSMasterKeyArn"),
                tags=_tags_from_list(tags),
            )
        )

    ec2 = gate.client("ec2", region_name=region)
    for v in gaps.attempt(f"ec2:DescribeVolumes {region}", lambda: _paginate(ec2, "describe_volumes", "Volumes"), []):
        res.ebs_volumes.append(
            EbsVolume(volume_id=v["VolumeId"], arn=f"arn:aws:ec2:{region}:{account_id}:volume/{v['VolumeId']}", size_gb=int(v.get("Size") or 0),
                      kms_key_arn=v.get("KmsKeyId"), tags=_tags_from_list(v.get("Tags")))
        )
    for s in gaps.attempt(f"ec2:DescribeSnapshots {region}", lambda: _paginate(ec2, "describe_snapshots", "Snapshots", OwnerIds=["self"]), []):
        res.ebs_snapshots.append(
            EbsSnapshot(snapshot_id=s["SnapshotId"], arn=f"arn:aws:ec2:{region}:{s.get('OwnerId', account_id)}:snapshot/{s['SnapshotId']}", volume_id=s.get("VolumeId", ""))
        )

    kms = gate.client("kms", region_name=region)
    for k in gaps.attempt(f"kms:ListKeys {region}", lambda: _paginate(kms, "list_keys", "Keys"), []):
        meta = gaps.attempt(f"kms:DescribeKey {k['KeyId']}", lambda kid=k["KeyId"]: kms.describe_key(KeyId=kid)["KeyMetadata"], None)
        if meta is None:
            continue
        policy = gaps.attempt(f"kms:GetKeyPolicy {k['KeyId']}", lambda kid=k["KeyId"]: kms.get_key_policy(KeyId=kid, PolicyName="default")["Policy"], None)
        tags = []
        if meta.get("KeyManager") == "CUSTOMER":
            tags = gaps.attempt(f"kms:ListResourceTags {k['KeyId']}", lambda kid=k["KeyId"]: kms.list_resource_tags(KeyId=kid).get("Tags", []), []) or []
        res.kms_keys.append(
            KmsKey(key_id=meta["KeyId"], arn=meta["Arn"], policy=load_policy_document(policy) if policy else None, key_state=meta.get("KeyState", ""),
                   key_manager=meta.get("KeyManager", "CUSTOMER"), origin=meta.get("Origin", "AWS_KMS"), description=meta.get("Description", ""),
                   tags={t["TagKey"]: t["TagValue"] for t in tags if "TagKey" in t})
        )

    backup = gate.client("backup", region_name=region)
    for v in gaps.attempt(f"backup:ListBackupVaults {region}", lambda: _paginate(backup, "list_backup_vaults", "BackupVaultList"), []):
        name = v["BackupVaultName"]
        policy = gaps.attempt(
            f"backup:GetBackupVaultAccessPolicy {name}", lambda n=name: backup.get_backup_vault_access_policy(BackupVaultName=n).get("Policy"), None,
            ("ResourceNotFoundException",),
        )
        mode = None
        immutable = False
        if v.get("MinRetentionDays") is not None or v.get("MaxRetentionDays") is not None or v.get("Locked"):
            lock_date = v.get("LockDate")
            if lock_date:
                mode = "COMPLIANCE"
                if isinstance(lock_date, str):
                    lock_date = _dt.datetime.fromisoformat(lock_date.replace("Z", "+00:00"))
                immutable = lock_date <= now
            else:
                mode = "GOVERNANCE"
        res.backup_vaults.append(
            BackupVault(name=name, arn=v["BackupVaultArn"], access_policy=load_policy_document(policy) if policy else None, lock_mode=mode,
                        lock_immutable=immutable, min_retention_days=v.get("MinRetentionDays"), max_retention_days=v.get("MaxRetentionDays"))
        )
        rps = gaps.attempt(
            f"backup:ListRecoveryPointsByBackupVault {name}",
            lambda n=name: _paginate(backup, "list_recovery_points_by_backup_vault", "RecoveryPoints", BackupVaultName=n),
            [],
        )
        for rp in rps or []:
            res.recovery_points.append(
                RecoveryPoint(arn=rp["RecoveryPointArn"], vault_arn=v["BackupVaultArn"], source_resource_arn=rp.get("ResourceArn", ""),
                              resource_type=rp.get("ResourceType", ""), status=rp.get("Status", ""), observed_via="vault")
            )
    jobs = gaps.attempt(f"backup:ListCopyJobs {region}", lambda: _paginate(backup, "list_copy_jobs", "CopyJobs", ByState="COMPLETED"), [])
    for job in jobs or []:
        dest_rp = job.get("DestinationRecoveryPointArn")
        if dest_rp and dest_rp.split(":")[4] != account_id:
            res.recovery_points.append(
                RecoveryPoint(arn=dest_rp, vault_arn=job.get("DestinationBackupVaultArn", ""), source_resource_arn=job.get("ResourceArn", ""),
                              resource_type=job.get("ResourceType", ""), status="COMPLETED", observed_via="copy_job")
            )


def collect_live(session: Any, regions: list[str], log: CallLog | None = None, now: _dt.datetime | None = None) -> tuple[Snapshot, CallLog]:
    """Build a Snapshot from a live account using only allowlisted read operations."""
    gate = ReadOnlyGate(session, log)
    gaps = _Gaps()
    now = now or _dt.datetime.now(_dt.timezone.utc)
    region = regions[0]
    ident = gate.client("sts", region_name=region).get_caller_identity()
    account_id = ident["Account"]
    iam_raw, fingerprints = _collect_iam(gate, gaps)
    org = _collect_scps(gate, account_id, region, gaps)
    if org is None:
        gaps.items.append("Service control policies could not be read from this account; results assume no SCP restricts it.")
    res = Resources()
    res.s3_buckets = _collect_s3(gate, region, gaps)
    for r in regions:
        _collect_region(gate, r, account_id, res, gaps, now)
    snap = Snapshot(
        account_id=account_id,
        regions=list(regions),
        iam=IamData.from_aws(iam_raw),
        organization=org,
        resources=res,
        access_key_fingerprints=fingerprints,
        source=f"live:{ident['Arn']}",
        coverage_gaps=gaps.items,
    )
    return snap, gate.log


def make_profile_mapper(session_factory: Callable[[str], Any], region: str, log: CallLog | None = None) -> Callable[[str], str | None]:
    """Map a local profile name to its principal ARN with sts:GetCallerIdentity (through the gate)."""

    def mapper(profile: str) -> str | None:
        try:
            gate = ReadOnlyGate(session_factory(profile), log)
            return gate.client("sts", region_name=region).get_caller_identity()["Arn"]
        except ReadOnlyViolation:
            raise
        except Exception:  # noqa: BLE001 - an unusable profile just stays unmapped
            return None

    return mapper
