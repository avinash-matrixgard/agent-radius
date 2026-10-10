"""The destructive-action catalog.

Each entry names a real IAM action, the resource type it acts on, an ARN
pattern, an irreversibility score and a one-line consequence.

Irreversibility:
  3 = data or evidence is gone and cannot be restored from inside the account
  2 = destructive, but recoverable if a surviving backup or rebuild path exists
  1 = weakens a protection, escalates privilege, or is reversible

Resource types marked as modelled are enumerated from the snapshot. For the
rest (EKS, ECR, Lambda, ...), v1 checks the account-wide ARN built from the
pattern, which answers "can the agent do this to every resource of the type".
"""

from __future__ import annotations

from dataclasses import dataclass

MODELLED_RESOURCE_TYPES = frozenset(
    {
        "s3_bucket",
        "s3_objects",
        "rds_instance",
        "rds_cluster",
        "rds_snapshot",
        "rds_cluster_snapshot",
        "dynamodb_table",
        "dynamodb_backup",
        "ebs_volume",
        "ebs_snapshot",
        "kms_key",
        "backup_vault",
        "recovery_point",
        "iam_role",
        "iam_user",
    }
)


@dataclass(frozen=True)
class CatalogAction:
    action: str
    resource_type: str
    arn_pattern: str
    irreversibility: int
    consequence: str
    category: str  # data_loss | backup_loss | protection_weakening | escalation | audit_blinding | disruption

    @property
    def service(self) -> str:
        return self.action.split(":", 1)[0]

    @property
    def modelled(self) -> bool:
        return self.resource_type in MODELLED_RESOURCE_TYPES


def _a(action: str, rtype: str, pattern: str, irr: int, consequence: str, category: str) -> CatalogAction:
    return CatalogAction(action, rtype, pattern, irr, consequence, category)


R = "{region}"
A = "{account}"

CATALOG: tuple[CatalogAction, ...] = (
    # ---- RDS ----------------------------------------------------------
    _a("rds:DeleteDBInstance", "rds_instance", f"arn:aws:rds:{R}:{A}:db:{{name}}", 3,
       "Deletes the database; with SkipFinalSnapshot and no surviving snapshot the data is gone.", "data_loss"),
    _a("rds:DeleteDBCluster", "rds_cluster", f"arn:aws:rds:{R}:{A}:cluster:{{name}}", 3,
       "Deletes the Aurora cluster and, by default, its automated backups.", "data_loss"),
    _a("rds:DeleteDBSnapshot", "rds_snapshot", f"arn:aws:rds:{R}:{A}:snapshot:{{name}}", 3,
       "Deletes a manual database snapshot; there is no undo.", "backup_loss"),
    _a("rds:DeleteDBClusterSnapshot", "rds_cluster_snapshot", f"arn:aws:rds:{R}:{A}:cluster-snapshot:{{name}}", 3,
       "Deletes a manual cluster snapshot; there is no undo.", "backup_loss"),
    _a("rds:DeleteDBInstanceAutomatedBackup", "account_wide", f"arn:aws:rds:{R}:{A}:auto-backup:*", 3,
       "Deletes retained automated backups of a deleted instance.", "backup_loss"),
    _a("rds:ModifyDBInstance", "rds_instance", f"arn:aws:rds:{R}:{A}:db:{{name}}", 2,
       "Can turn off deletion protection or set backup retention to 0, which deletes automated backups.", "protection_weakening"),
    _a("rds:ModifyDBCluster", "rds_cluster", f"arn:aws:rds:{R}:{A}:cluster:{{name}}", 2,
       "Can turn off deletion protection on the cluster or shorten backup retention.", "protection_weakening"),
    # ---- S3 -----------------------------------------------------------
    _a("s3:DeleteBucket", "s3_bucket", "arn:aws:s3:::{name}", 2,
       "Deletes the bucket once empty; the name can then be claimed by anyone.", "data_loss"),
    _a("s3:DeleteObject", "s3_objects", "arn:aws:s3:::{name}/*", 3,
       "Permanently deletes objects in an unversioned bucket; adds delete markers in a versioned one.", "data_loss"),
    _a("s3:DeleteObjectVersion", "s3_objects", "arn:aws:s3:::{name}/*", 3,
       "Permanently deletes specific object versions, including the history versioning keeps.", "backup_loss"),
    _a("s3:BypassGovernanceRetention", "s3_objects", "arn:aws:s3:::{name}/*", 2,
       "Lets deletes go through Object Lock governance-mode retention.", "protection_weakening"),
    _a("s3:PutBucketVersioning", "s3_bucket", "arn:aws:s3:::{name}", 1,
       "Can suspend versioning so later deletes are permanent.", "protection_weakening"),
    _a("s3:PutLifecycleConfiguration", "s3_bucket", "arn:aws:s3:::{name}", 2,
       "Can add an expiration rule that deletes every object and old version within a day.", "data_loss"),
    _a("s3:PutBucketPolicy", "s3_bucket", "arn:aws:s3:::{name}", 1,
       "Can rewrite the bucket policy, removing deny guardrails or exposing data publicly.", "protection_weakening"),
    _a("s3:DeleteBucketPolicy", "s3_bucket", "arn:aws:s3:::{name}", 1,
       "Removes the bucket policy and every deny guardrail in it.", "protection_weakening"),
    _a("s3:PutBucketObjectLockConfiguration", "s3_bucket", "arn:aws:s3:::{name}", 1,
       "Can change default retention for new objects (cannot shorten compliance-mode locks already set).", "protection_weakening"),
    _a("s3:PutReplicationConfiguration", "s3_bucket", "arn:aws:s3:::{name}", 1,
       "Can remove or redirect replication so new data stops reaching the copy.", "protection_weakening"),
    # ---- DynamoDB -----------------------------------------------------
    _a("dynamodb:DeleteTable", "dynamodb_table", f"arn:aws:dynamodb:{R}:{A}:table/{{name}}", 3,
       "Deletes the table and every item in it.", "data_loss"),
    _a("dynamodb:DeleteBackup", "dynamodb_backup", f"arn:aws:dynamodb:{R}:{A}:table/{{name}}/backup/*", 3,
       "Deletes on-demand backups, including the system backup kept after a PITR table is deleted.", "backup_loss"),
    _a("dynamodb:UpdateContinuousBackups", "dynamodb_table", f"arn:aws:dynamodb:{R}:{A}:table/{{name}}", 2,
       "Can turn off point-in-time recovery, discarding the restore window.", "protection_weakening"),
    _a("dynamodb:UpdateTable", "dynamodb_table", f"arn:aws:dynamodb:{R}:{A}:table/{{name}}", 1,
       "Can turn off deletion protection on the table.", "protection_weakening"),
    _a("dynamodb:DeleteItem", "dynamodb_table", f"arn:aws:dynamodb:{R}:{A}:table/{{name}}", 2,
       "Deletes items one by one; without PITR they cannot be restored.", "data_loss"),
    _a("dynamodb:BatchWriteItem", "dynamodb_table", f"arn:aws:dynamodb:{R}:{A}:table/{{name}}", 2,
       "Deletes or overwrites up to 25 items per call.", "data_loss"),
    # ---- EC2 / EBS ----------------------------------------------------
    _a("ec2:DeleteVolume", "ebs_volume", f"arn:aws:ec2:{R}:{A}:volume/{{name}}", 3,
       "Deletes the EBS volume and its data.", "data_loss"),
    _a("ec2:DeleteSnapshot", "ebs_snapshot", f"arn:aws:ec2:{R}::snapshot/{{name}}", 3,
       "Deletes an EBS snapshot; there is no undo outside the Recycle Bin.", "backup_loss"),
    _a("ec2:TerminateInstances", "account_wide", f"arn:aws:ec2:{R}:{A}:instance/*", 2,
       "Terminates instances; instance-store data and delete-on-termination volumes are lost.", "disruption"),
    # ---- KMS ----------------------------------------------------------
    _a("kms:ScheduleKeyDeletion", "kms_key", f"arn:aws:kms:{R}:{A}:key/{{name}}", 3,
       "After the 7 to 30 day wait, every ciphertext under the key is unrecoverable, backups included.", "data_loss"),
    _a("kms:DisableKey", "kms_key", f"arn:aws:kms:{R}:{A}:key/{{name}}", 1,
       "Makes all data encrypted under the key unreadable until the key is re-enabled.", "disruption"),
    _a("kms:PutKeyPolicy", "kms_key", f"arn:aws:kms:{R}:{A}:key/{{name}}", 2,
       "Can lock every other principal, including admins, out of the key.", "protection_weakening"),
    _a("kms:DeleteImportedKeyMaterial", "kms_key", f"arn:aws:kms:{R}:{A}:key/{{name}}", 3,
       "Removes imported key material; data stays unreadable unless the same material is re-imported.", "data_loss"),
    _a("kms:CreateGrant", "kms_key", f"arn:aws:kms:{R}:{A}:key/{{name}}", 1,
       "Can hand key permissions to another principal.", "escalation"),
    # ---- AWS Backup ---------------------------------------------------
    _a("backup:DeleteRecoveryPoint", "recovery_point", f"arn:aws:backup:{R}:{A}:recovery-point:{{name}}", 3,
       "Deletes a backup recovery point; there is no undo.", "backup_loss"),
    _a("backup:UpdateRecoveryPointLifecycle", "recovery_point", f"arn:aws:backup:{R}:{A}:recovery-point:{{name}}", 2,
       "Can shorten retention so recovery points expire early.", "backup_loss"),
    _a("backup:DeleteBackupVault", "backup_vault", f"arn:aws:backup:{R}:{A}:backup-vault:{{name}}", 2,
       "Deletes an empty vault, along with its access policy and lock.", "protection_weakening"),
    _a("backup:DeleteBackupVaultLockConfiguration", "backup_vault", f"arn:aws:backup:{R}:{A}:backup-vault:{{name}}", 1,
       "Removes a governance-mode (or not yet immutable) vault lock.", "protection_weakening"),
    _a("backup:PutBackupVaultAccessPolicy", "backup_vault", f"arn:aws:backup:{R}:{A}:backup-vault:{{name}}", 1,
       "Can replace the vault policy and remove the deny that protects recovery points.", "protection_weakening"),
    _a("backup:DeleteBackupVaultAccessPolicy", "backup_vault", f"arn:aws:backup:{R}:{A}:backup-vault:{{name}}", 1,
       "Removes the vault access policy and every deny in it.", "protection_weakening"),
    _a("backup:DeleteBackupPlan", "account_wide", f"arn:aws:backup:{R}:{A}:backup-plan:*", 1,
       "Stops future backups silently.", "protection_weakening"),
    # ---- IAM ----------------------------------------------------------
    _a("iam:DeleteRole", "iam_role", f"arn:aws:iam::{A}:role/{{name}}", 2,
       "Deletes a role; workloads using it fail until it is recreated.", "disruption"),
    _a("iam:AttachRolePolicy", "iam_role", f"arn:aws:iam::{A}:role/{{name}}", 1,
       "Can attach AdministratorAccess to a role, including the agent's own.", "escalation"),
    _a("iam:PutRolePolicy", "iam_role", f"arn:aws:iam::{A}:role/{{name}}", 1,
       "Can write an inline policy granting anything to a role, including the agent's own.", "escalation"),
    _a("iam:UpdateAssumeRolePolicy", "iam_role", f"arn:aws:iam::{A}:role/{{name}}", 1,
       "Can let any principal, including outside accounts, assume the role.", "escalation"),
    _a("iam:DeleteRolePermissionsBoundary", "iam_role", f"arn:aws:iam::{A}:role/{{name}}", 1,
       "Removes the permissions boundary that caps a role.", "escalation"),
    _a("iam:CreateAccessKey", "iam_user", f"arn:aws:iam::{A}:user/{{name}}", 1,
       "Can mint long-lived access keys for another user.", "escalation"),
    _a("iam:AttachUserPolicy", "iam_user", f"arn:aws:iam::{A}:user/{{name}}", 1,
       "Can attach AdministratorAccess to a user.", "escalation"),
    _a("iam:PutUserPolicy", "iam_user", f"arn:aws:iam::{A}:user/{{name}}", 1,
       "Can write an inline policy granting anything to a user.", "escalation"),
    _a("iam:DeleteUser", "iam_user", f"arn:aws:iam::{A}:user/{{name}}", 2,
       "Deletes a user and every key and login it holds.", "disruption"),
    _a("iam:CreatePolicyVersion", "account_wide", f"arn:aws:iam::{A}:policy/*", 1,
       "Can rewrite any customer managed policy, including the one that limits the agent.", "escalation"),
    # ---- Organizations --------------------------------------------------
    _a("organizations:LeaveOrganization", "account_wide", "*", 2,
       "Removes the account from the organization and every SCP guardrail with it.", "protection_weakening"),
    # ---- Containers, functions, data stores ------------------------------
    _a("eks:DeleteCluster", "account_wide", f"arn:aws:eks:{R}:{A}:cluster/*", 2,
       "Deletes the Kubernetes control plane; workloads stop and cluster state is lost.", "disruption"),
    _a("ecr:DeleteRepository", "account_wide", f"arn:aws:ecr:{R}:{A}:repository/*", 3,
       "With force, deletes the repository and every image in it.", "data_loss"),
    _a("ecr:BatchDeleteImage", "account_wide", f"arn:aws:ecr:{R}:{A}:repository/*", 3,
       "Deletes container images; tags pointing at them break.", "data_loss"),
    _a("lambda:DeleteFunction", "account_wide", f"arn:aws:lambda:{R}:{A}:function:*", 2,
       "Deletes the function and all its versions.", "disruption"),
    _a("elasticfilesystem:DeleteFileSystem", "account_wide", f"arn:aws:elasticfilesystem:{R}:{A}:file-system/*", 3,
       "Deletes the EFS file system and every file on it.", "data_loss"),
    _a("elasticache:DeleteCacheCluster", "account_wide", f"arn:aws:elasticache:{R}:{A}:cluster:*", 2,
       "Deletes the cache cluster and its in-memory data.", "data_loss"),
    _a("elasticache:DeleteReplicationGroup", "account_wide", f"arn:aws:elasticache:{R}:{A}:replicationgroup:*", 2,
       "Deletes the replication group and its data.", "data_loss"),
    _a("redshift:DeleteCluster", "account_wide", f"arn:aws:redshift:{R}:{A}:cluster:*", 3,
       "Deletes the warehouse; without a final snapshot the data is gone.", "data_loss"),
    _a("es:DeleteDomain", "account_wide", f"arn:aws:es:{R}:{A}:domain/*", 3,
       "Deletes the OpenSearch domain and its indices.", "data_loss"),
    _a("secretsmanager:DeleteSecret", "account_wide", f"arn:aws:secretsmanager:{R}:{A}:secret:*", 2,
       "With ForceDeleteWithoutRecovery the secret is gone immediately.", "data_loss"),
    # ---- Logs, audit, detection -----------------------------------------
    _a("logs:DeleteLogGroup", "account_wide", f"arn:aws:logs:{R}:{A}:log-group:*", 3,
       "Deletes the log group and all its events, including audit evidence.", "audit_blinding"),
    _a("cloudtrail:StopLogging", "account_wide", f"arn:aws:cloudtrail:{R}:{A}:trail/*", 1,
       "Stops the audit trail so later actions leave no record.", "audit_blinding"),
    _a("cloudtrail:DeleteTrail", "account_wide", f"arn:aws:cloudtrail:{R}:{A}:trail/*", 1,
       "Deletes the trail configuration.", "audit_blinding"),
    _a("guardduty:DeleteDetector", "account_wide", f"arn:aws:guardduty:{R}:{A}:detector/*", 1,
       "Turns off threat detection and deletes its findings.", "audit_blinding"),
    _a("config:DeleteConfigurationRecorder", "account_wide", "*", 1,
       "Stops AWS Config from recording resource changes.", "audit_blinding"),
    # ---- DNS --------------------------------------------------------------
    _a("route53:DeleteHostedZone", "account_wide", "arn:aws:route53:::hostedzone/*", 2,
       "Deletes the zone; a recreated zone gets new name servers, so the domain goes dark until delegation is fixed.", "disruption"),
    _a("route53:ChangeResourceRecordSets", "account_wide", "arn:aws:route53:::hostedzone/*", 2,
       "Can delete or repoint DNS records for the whole domain.", "disruption"),
)


_BY_ACTION = {c.action.lower(): c for c in CATALOG}


def by_action(action: str) -> CatalogAction | None:
    return _BY_ACTION.get(action.lower())


def catalog_actions() -> list[str]:
    return [c.action for c in CATALOG]


def account_wide_arn(entry: CatalogAction, account_id: str, region: str) -> str:
    return entry.arn_pattern.replace("{account}", account_id).replace("{region}", region)
