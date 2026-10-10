from __future__ import annotations

import re

from agent_radius.catalog import CATALOG, MODELLED_RESOURCE_TYPES, account_wide_arn


def test_catalog_shape():
    assert len(CATALOG) >= 60
    actions = [c.action for c in CATALOG]
    assert len(actions) == len(set(a.lower() for a in actions))
    for c in CATALOG:
        assert re.fullmatch(r"[a-z0-9-]+:[A-Z][A-Za-z0-9]+", c.action), c.action
        assert c.irreversibility in (1, 2, 3)
        assert c.consequence.endswith(".") and len(c.consequence) < 160
        assert c.resource_type in MODELLED_RESOURCE_TYPES or c.resource_type == "account_wide"
        assert c.category in {"data_loss", "backup_loss", "protection_weakening", "escalation", "audit_blinding", "disruption"}
        if not c.modelled:
            arn = account_wide_arn(c, "111122223333", "us-east-1")
            assert "{" not in arn


def test_required_actions_present():
    required = {
        "rds:DeleteDBInstance", "rds:DeleteDBCluster", "rds:DeleteDBSnapshot", "rds:ModifyDBInstance", "s3:DeleteBucket",
        "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutBucketVersioning", "s3:PutLifecycleConfiguration",
        "s3:PutBucketPolicy", "dynamodb:DeleteTable", "dynamodb:DeleteBackup", "dynamodb:UpdateContinuousBackups",
        "dynamodb:UpdateTable", "ec2:DeleteVolume", "ec2:DeleteSnapshot", "ec2:TerminateInstances", "kms:ScheduleKeyDeletion",
        "kms:DisableKey", "kms:PutKeyPolicy", "backup:DeleteRecoveryPoint", "backup:DeleteBackupVault",
        "backup:DeleteBackupVaultLockConfiguration", "backup:UpdateRecoveryPointLifecycle", "iam:DeleteRole",
        "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:CreateAccessKey", "iam:DeleteUser", "organizations:LeaveOrganization",
        "eks:DeleteCluster", "ecr:DeleteRepository", "logs:DeleteLogGroup", "cloudtrail:StopLogging", "cloudtrail:DeleteTrail",
        "route53:DeleteHostedZone", "secretsmanager:DeleteSecret", "lambda:DeleteFunction",
        "elasticfilesystem:DeleteFileSystem", "elasticache:DeleteCacheCluster",
    }
    assert required <= {c.action for c in CATALOG}
