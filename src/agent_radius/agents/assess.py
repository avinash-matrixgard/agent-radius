"""Pure assessment functions shared by the specialists and the Verifier.

Everything here is a deterministic function of (snapshot, evaluator,
principal, resource). The Verifier re-runs these to reproduce findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agent_radius.agents.tools import Toolbox
from agent_radius.catalog import by_action
from agent_radius.iam.evaluator import Decision, Outcome
from agent_radius.snapshot.model import (
    BackupVault,
    DynamoTable,
    EbsVolume,
    RdsCluster,
    RdsInstance,
    ResourceRef,
    S3Bucket,
)

SAFE, POSSIBLE, LOST = 0, 1, 2
STATUS_NAME = {SAFE: "SAFE", POSSIBLE: "POSSIBLE_LOSS", LOST: "LOST"}
# How a permission strength reads in a sentence ("rds:DeleteDBInstance allowed").
WORD = {SAFE: "denied", POSSIBLE: "conditional", LOST: "allowed"}

STATEFUL_TYPES = ("rds_cluster", "rds_instance", "dynamodb_table", "s3_bucket", "ebs_volume")

_STATE_RE = re.compile(r"(tfstate|tf-state|tf_state|terraform-state|terraform_state|terraformstate|terraform\.tfstate)", re.I)


def perm(decision: Decision) -> int:
    if decision.outcome == Outcome.ALLOW:
        return LOST
    if decision.outcome == Outcome.CONDITIONAL:
        return POSSIBLE
    return SAFE


def is_state_bucket(bucket: S3Bucket) -> bool:
    if _STATE_RE.search(bucket.name):
        return True
    for key, value in bucket.tags.items():
        if _STATE_RE.search(key) or _STATE_RE.search(value):
            return True
        if key.lower() in ("purpose", "usage", "role") and "terraform" in value.lower():
            return True
    return False


# --------------------------------------------------------------------------
# Effective permission: IAM decision plus resource-level protections
# --------------------------------------------------------------------------


@dataclass
class Effective:
    decision: Decision
    effective: bool
    irreversibility: int
    notes: list[str] = field(default_factory=list)
    companions: list[Decision] = field(default_factory=list)


def effective_permission(tb: Toolbox, principal: str, action: str, ref: ResourceRef | None, resource_arn: str) -> Effective:
    """Evaluate ``action`` and apply resource settings that block it in practice."""
    entry = by_action(action)
    irr = entry.irreversibility if entry else 1
    decision = tb.evaluate(principal, action, resource_arn)
    eff = Effective(decision, decision.outcome.permits, irr)
    if not decision.outcome.permits or ref is None:
        return eff
    obj = ref.obj

    def companion(act: str, arn: str) -> int:
        d = tb.evaluate(principal, act, arn)
        eff.companions.append(d)
        return perm(d)

    if action == "rds:DeleteDBInstance" and isinstance(obj, RdsInstance) and obj.deletion_protection:
        if companion("rds:ModifyDBInstance", obj.arn) == SAFE:
            eff.effective = False
            eff.notes.append("deletion protection is on and the agent cannot call rds:ModifyDBInstance to turn it off")
        else:
            eff.notes.append("deletion protection is on, but the agent can turn it off with rds:ModifyDBInstance")
    elif action == "rds:DeleteDBCluster" and isinstance(obj, RdsCluster) and obj.deletion_protection:
        if companion("rds:ModifyDBCluster", obj.arn) == SAFE:
            eff.effective = False
            eff.notes.append("deletion protection is on and the agent cannot call rds:ModifyDBCluster to turn it off")
        else:
            eff.notes.append("deletion protection is on, but the agent can turn it off with rds:ModifyDBCluster")
    elif action == "dynamodb:DeleteTable" and isinstance(obj, DynamoTable) and obj.deletion_protection:
        if companion("dynamodb:UpdateTable", obj.arn) == SAFE:
            eff.effective = False
            eff.notes.append("deletion protection is on and the agent cannot call dynamodb:UpdateTable to turn it off")
        else:
            eff.notes.append("deletion protection is on, but the agent can turn it off with dynamodb:UpdateTable")
    elif isinstance(obj, S3Bucket):
        lock = obj.object_lock
        locked_compliance = lock.enabled and lock.mode == "COMPLIANCE"
        locked_governance = lock.enabled and lock.mode == "GOVERNANCE"
        if action == "s3:DeleteObject":
            if obj.versioning == "Enabled" or locked_compliance:
                eff.irreversibility = 1
                eff.notes.append("bucket is versioned: deletes add delete markers and earlier versions remain")
        elif action == "s3:DeleteObjectVersion":
            if obj.mfa_delete:
                eff.effective = False
                eff.notes.append("MFA delete is enabled: version deletes need the root user's MFA device")
            elif locked_compliance:
                eff.effective = False
                eff.notes.append("Object Lock compliance mode: locked versions cannot be deleted before retention ends")
            elif locked_governance and companion("s3:BypassGovernanceRetention", obj.objects_arn) == SAFE:
                eff.effective = False
                eff.notes.append("Object Lock governance mode and the agent cannot bypass governance retention")
        elif action == "s3:PutLifecycleConfiguration" and locked_compliance:
            eff.irreversibility = 1
            eff.notes.append("Object Lock compliance mode: lifecycle rules cannot expire locked versions early")
    elif ref.resource_type in ("recovery_point", "backup_vault"):
        vault = obj if isinstance(obj, BackupVault) else tb.snapshot.vault_for_arn(resource_arn)
        if vault is not None and vault.lock_mode:
            immutable = vault.lock_mode == "COMPLIANCE" and vault.lock_immutable
            if action in ("backup:DeleteRecoveryPoint", "backup:UpdateRecoveryPointLifecycle"):
                if immutable:
                    eff.effective = False
                    eff.notes.append("vault lock in compliance mode: recovery points cannot be deleted or shortened")
                elif companion("backup:DeleteBackupVaultLockConfiguration", vault.arn) == SAFE:
                    eff.effective = False
                    eff.notes.append("vault lock is set and the agent cannot remove it")
                else:
                    eff.notes.append("vault lock is set but the agent can remove it first")
            elif action == "backup:DeleteBackupVaultLockConfiguration" and immutable:
                eff.effective = False
                eff.notes.append("vault lock is in compliance mode and already immutable")
    elif ref.resource_type == "kms_key":
        if getattr(obj, "key_manager", "CUSTOMER") == "AWS" and action != "kms:CreateGrant":
            eff.effective = False
            eff.notes.append("AWS managed key: customers cannot delete, disable or change it")
        elif action == "kms:DeleteImportedKeyMaterial" and getattr(obj, "origin", "AWS_KMS") != "EXTERNAL":
            eff.effective = False
            eff.notes.append(f"key origin is {getattr(obj, 'origin', 'AWS_KMS')}: there is no imported key material to delete")
    return eff


# --------------------------------------------------------------------------
# Backup survivability
# --------------------------------------------------------------------------


@dataclass
class Copy:
    kind: str
    arn: str | None
    status: int
    reason: str
    location: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "arn": self.arn,
            "status": STATUS_NAME[self.status],
            "reason": self.reason,
            "location": self.location,
        }


@dataclass
class Assessment:
    principal: str
    resource: str
    resource_type: str
    verdict: str
    primary: int
    primary_reason: str
    copies: list[Copy]
    decisions: list[Decision]
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "resource": self.resource,
            "resource_type": self.resource_type,
            "verdict": self.verdict,
            "primary": STATUS_NAME[self.primary],
            "primary_reason": self.primary_reason,
            "copies": [c.to_dict() for c in self.copies],
            "decisions": [
                {"action": d.action, "resource": d.resource_arn, "outcome": d.outcome.value, "statements": d.evidence_ids}
                for d in self.decisions
            ],
            "notes": list(self.notes),
        }


def combine_verdict(primary: int, copies: list[Copy]) -> str:
    if primary == SAFE:
        return "SURVIVES"
    if any(c.status == SAFE for c in copies):
        return "SURVIVES"
    if primary == LOST and all(c.status == LOST for c in copies):
        return "AT_RISK"
    return "PARTIAL"


class _Ctx:
    def __init__(self, tb: Toolbox, principal: str) -> None:
        self.tb = tb
        self.principal = principal
        self.decisions: list[Decision] = []

    def p(self, action: str, arn: str) -> int:
        d = self.tb.evaluate(self.principal, action, arn)
        self.decisions.append(d)
        return perm(d)

    def p2(self, action: str, arn: str, policy_actions: tuple[str, ...], policy_arn: str) -> int:
        """Direct path, or two steps: rewrite/remove the resource policy, then act."""
        direct = self.p(action, arn)
        if direct == LOST:
            return direct
        rewrite = max(self.p(a, policy_arn) for a in policy_actions)
        if rewrite == SAFE:
            return direct
        d = self.tb.evaluate(self.principal, action, arn, ignore_resource_policy=True)
        self.decisions.append(d)
        return max(direct, min(rewrite, perm(d)))

    def wide(self, action: str) -> str:
        entry = by_action(action)
        assert entry is not None
        return self.tb.account_wide_arn(entry)


def _recovery_point_copies(ctx: _Ctx, resource_arn: str) -> list[Copy]:
    snap = ctx.tb.snapshot
    out: list[Copy] = []
    for rp in snap.resources.recovery_points:
        if rp.source_resource_arn != resource_arn:
            continue
        location = f"account {rp.account_id}, {rp.region}"
        if rp.account_id != snap.account_id:
            out.append(Copy("aws_backup_recovery_point", rp.arn, SAFE, "copy lives in another account", location))
            continue
        vault = snap.vault_for_arn(rp.arn)
        if vault is not None and vault.access_policy:
            pol = ("backup:DeleteBackupVaultAccessPolicy", "backup:PutBackupVaultAccessPolicy")
            kill = max(
                ctx.p2("backup:DeleteRecoveryPoint", rp.arn, pol, vault.arn),
                ctx.p2("backup:UpdateRecoveryPointLifecycle", rp.arn, pol, vault.arn),
            )
        else:
            kill = max(ctx.p("backup:DeleteRecoveryPoint", rp.arn), ctx.p("backup:UpdateRecoveryPointLifecycle", rp.arn))
        if vault is not None and vault.lock_mode == "COMPLIANCE" and vault.lock_immutable:
            out.append(Copy("aws_backup_recovery_point", rp.arn, SAFE, f"vault {vault.name} has an immutable compliance-mode lock", location))
            continue
        if vault is not None and vault.lock_mode:
            unlock = ctx.p("backup:DeleteBackupVaultLockConfiguration", vault.arn)
            status = min(unlock, kill)
            reason = (
                f"vault {vault.name} has a {vault.lock_mode.lower()} lock the agent can remove, then delete"
                if status
                else f"vault {vault.name} lock holds against this agent"
            )
            out.append(Copy("aws_backup_recovery_point", rp.arn, status, reason, location))
            continue
        reason = "agent can delete or expire it" if kill else "agent cannot delete or expire it"
        out.append(Copy("aws_backup_recovery_point", rp.arn, kill, reason, location))
    return out


def _assess_rds(ctx: _Ctx, obj: RdsInstance | RdsCluster, cluster: bool) -> tuple[int, str, list[Copy], list[str]]:
    snap = ctx.tb.snapshot
    notes: list[str] = []
    delete_action = "rds:DeleteDBCluster" if cluster else "rds:DeleteDBInstance"
    modify_action = "rds:ModifyDBCluster" if cluster else "rds:ModifyDBInstance"
    delete = ctx.p(delete_action, obj.arn)
    modify = ctx.p(modify_action, obj.arn)
    primary = min(delete, modify) if obj.deletion_protection else delete
    reason = f"{delete_action} {WORD[delete]}"
    if obj.deletion_protection:
        reason += f"; deletion protection on, {modify_action} {WORD[modify]}"
    copies: list[Copy] = []
    if obj.backup_retention_period > 0:
        auto_kill = max(primary, modify)
        if not cluster:
            auto_kill = max(auto_kill, ctx.p("rds:DeleteDBInstanceAutomatedBackup", ctx.wide("rds:DeleteDBInstanceAutomatedBackup")))
        copies.append(
            Copy(
                "rds_automated_backups",
                None,
                auto_kill,
                f"{obj.backup_retention_period} day automated backups are deleted with the database by default"
                " or by setting retention to 0",
                f"account {snap.account_id}",
            )
        )
    snap_kind = "cluster" if cluster else "instance"
    snap_action = "rds:DeleteDBClusterSnapshot" if cluster else "rds:DeleteDBSnapshot"
    for s in snap.resources.rds_snapshots:
        if s.source_identifier != obj.identifier or s.source_kind != snap_kind:
            continue
        if s.snapshot_type == "automated":
            continue  # covered by the automated-backups copy above
        location = f"account {s.account_id}, {s.region}"
        if s.account_id != snap.account_id:
            copies.append(Copy("rds_snapshot", s.arn, SAFE, "copy lives in another account", location))
            continue
        status = ctx.p(snap_action, s.arn)
        copies.append(Copy("rds_snapshot", s.arn, status, f"{snap_action} {WORD[status]}", location))
    copies += _recovery_point_copies(ctx, obj.arn)
    return primary, reason, copies, notes


def _assess_dynamo(ctx: _Ctx, t: DynamoTable) -> tuple[int, str, list[Copy], list[str]]:
    snap = ctx.tb.snapshot
    delete = ctx.p("dynamodb:DeleteTable", t.arn)
    update = ctx.p("dynamodb:UpdateTable", t.arn)
    table_kill = min(delete, update) if t.deletion_protection else delete
    items = max(ctx.p("dynamodb:DeleteItem", t.arn), ctx.p("dynamodb:BatchWriteItem", t.arn))
    primary = max(table_kill, items)
    reason = f"dynamodb:DeleteTable {WORD[delete]}"
    if t.deletion_protection:
        reason += f"; deletion protection on, dynamodb:UpdateTable {WORD[update]}"
    reason += f"; item deletes {WORD[items]}"
    copies: list[Copy] = []
    if t.pitr_enabled:
        kill = max(ctx.p("dynamodb:UpdateContinuousBackups", t.arn), ctx.p("dynamodb:DeleteBackup", t.backup_wildcard_arn))
        copies.append(
            Copy(
                "dynamodb_pitr",
                None,
                kill,
                "point-in-time recovery can be switched off, and the system backup kept after a delete can be deleted"
                if kill
                else "agent can neither switch off PITR nor delete its backups",
                f"account {snap.account_id}",
            )
        )
    for b in t.backups:
        status = ctx.p("dynamodb:DeleteBackup", b.arn)
        copies.append(Copy("dynamodb_backup", b.arn, status, f"dynamodb:DeleteBackup {WORD[status]}", f"account {snap.account_id}"))
    copies += _recovery_point_copies(ctx, t.arn)
    return primary, reason, copies, []


_BUCKET_POLICY_ACTIONS = ("s3:DeleteBucketPolicy", "s3:PutBucketPolicy")


def _s3p(ctx: _Ctx, b: S3Bucket, action: str, arn: str) -> int:
    if b.policy:
        return ctx.p2(action, arn, _BUCKET_POLICY_ACTIONS, b.arn)
    return ctx.p(action, arn)


def _s3_versions_kill(ctx: _Ctx, b: S3Bucket) -> tuple[int, str]:
    lock = b.object_lock
    if b.mfa_delete:
        return SAFE, "MFA delete protects object versions"
    if lock.enabled and lock.mode == "COMPLIANCE":
        return SAFE, "Object Lock compliance mode protects object versions until retention ends"
    if lock.enabled and lock.mode == "GOVERNANCE":
        status = min(_s3p(ctx, b, "s3:BypassGovernanceRetention", b.objects_arn), _s3p(ctx, b, "s3:DeleteObjectVersion", b.objects_arn))
        return status, "governance-mode lock " + ("can be bypassed by the agent" if status else "holds against this agent")
    status = max(_s3p(ctx, b, "s3:DeleteObjectVersion", b.objects_arn), _s3p(ctx, b, "s3:PutLifecycleConfiguration", b.arn))
    return status, "agent can delete versions or expire them with a lifecycle rule" if status else "agent cannot delete or expire versions"


def _assess_s3(ctx: _Ctx, b: S3Bucket) -> tuple[int, str, list[Copy], list[str]]:
    snap = ctx.tb.snapshot
    delete = _s3p(ctx, b, "s3:DeleteObject", b.objects_arn)
    lifecycle = _s3p(ctx, b, "s3:PutLifecycleConfiguration", b.arn)
    primary = max(delete, lifecycle)
    reason = f"s3:DeleteObject {WORD[delete]}; s3:PutLifecycleConfiguration {WORD[lifecycle]}"
    copies: list[Copy] = []
    notes: list[str] = []
    if b.versioning == "Enabled" or b.object_lock.enabled:
        status, why = _s3_versions_kill(ctx, b)
        copies.append(Copy("s3_object_versions", b.objects_arn, status, why, f"account {snap.account_id}"))
    elif b.versioning == "Suspended":
        notes.append("versioning is suspended: only versions written before suspension are kept")
    for rule in b.replication:
        if rule.status != "Enabled":
            continue
        dest = snap.bucket_for_arn(rule.destination_bucket_arn)
        dest_account = rule.destination_account or (snap.account_id if dest is not None else None)
        location = f"account {dest_account or 'unknown'}, {rule.destination_region or 'unknown region'}"
        if dest_account and dest_account != snap.account_id:
            copies.append(Copy("s3_replica", rule.destination_bucket_arn, SAFE, "replica lives in another account", location))
        elif dest is None:
            copies.append(Copy("s3_replica", rule.destination_bucket_arn, POSSIBLE, "replica bucket is not in the snapshot, so its protection is unknown", location))
        else:
            if dest.versioning == "Enabled" or dest.object_lock.enabled:
                status, why = _s3_versions_kill(ctx, dest)
            else:
                status = _s3p(ctx, dest, "s3:DeleteObject", dest.objects_arn)
                why = f"replica is unversioned; s3:DeleteObject {WORD[status]}"
            copies.append(Copy("s3_replica", dest.arn, status, why, location))
    copies += _recovery_point_copies(ctx, b.arn)
    return primary, reason, copies, notes


def _assess_ebs(ctx: _Ctx, v: EbsVolume) -> tuple[int, str, list[Copy], list[str]]:
    snap = ctx.tb.snapshot
    primary = ctx.p("ec2:DeleteVolume", v.arn)
    reason = f"ec2:DeleteVolume {WORD[primary]}"
    copies: list[Copy] = []
    for s in snap.resources.ebs_snapshots:
        if s.volume_id != v.volume_id:
            continue
        location = f"account {s.account_id}, {s.region}"
        if s.account_id != snap.account_id:
            copies.append(Copy("ebs_snapshot", s.arn, SAFE, "copy lives in another account", location))
            continue
        status = ctx.p("ec2:DeleteSnapshot", s.arn)
        copies.append(Copy("ebs_snapshot", s.arn, status, f"ec2:DeleteSnapshot {WORD[status]}", location))
    copies += _recovery_point_copies(ctx, v.arn)
    return primary, reason, copies, []


def assess_survivability(tb: Toolbox, principal: str, ref: ResourceRef) -> Assessment:
    ctx = _Ctx(tb, principal)
    obj = ref.obj
    if ref.resource_type == "rds_instance":
        primary, reason, copies, notes = _assess_rds(ctx, obj, cluster=False)
    elif ref.resource_type == "rds_cluster":
        primary, reason, copies, notes = _assess_rds(ctx, obj, cluster=True)
    elif ref.resource_type == "dynamodb_table":
        primary, reason, copies, notes = _assess_dynamo(ctx, obj)
    elif ref.resource_type == "s3_bucket":
        primary, reason, copies, notes = _assess_s3(ctx, obj)
    elif ref.resource_type == "ebs_volume":
        primary, reason, copies, notes = _assess_ebs(ctx, obj)
    else:
        raise ValueError(f"{ref.resource_type} is not a stateful resource type")

    key_arn = getattr(obj, "kms_key_arn", None)
    if key_arn and tb.snapshot.kms_key(key_arn) is not None:
        if ctx.p("kms:ScheduleKeyDeletion", key_arn) != SAFE:
            notes.append(
                f"the agent can schedule deletion of KMS key {key_arn}; after the waiting period, every same-account"
                " copy encrypted under it is unreadable too"
            )
    if not copies:
        notes.append("no backup copy of this resource was found in the snapshot")
    verdict = combine_verdict(primary, copies)
    return Assessment(principal, ref.arn, ref.resource_type, verdict, primary, reason, copies, ctx.decisions, notes)
