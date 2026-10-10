"""The live collector, run against moto (never a real account)."""

from __future__ import annotations

import json

import boto3
from moto import mock_aws

from agent_radius.agents.orchestrator import RunOptions, run_scan
from agent_radius.snapshot.collector import LIVE_OPERATIONS, collect_live
from agent_radius.snapshot.fixture import snapshot_from_dict

REGION = "us-east-1"
ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}


def _seed() -> dict:
    iam = boto3.client("iam", region_name=REGION)
    iam.create_role(RoleName="agent", AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": []}))
    pol = iam.create_policy(PolicyName="AgentAdmin", PolicyDocument=json.dumps(ADMIN_DOC))["Policy"]["Arn"]
    iam.attach_role_policy(RoleName="agent", PolicyArn=pol)
    iam.create_user(UserName="ci")
    key_id = iam.create_access_key(UserName="ci")["AccessKey"]["AccessKeyId"]

    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket="acme-tfstate-prod")
    s3.create_bucket(Bucket="acme-prod-assets")
    s3.put_bucket_versioning(Bucket="acme-prod-assets", VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket="acme-prod-assets", Tagging={"TagSet": [{"Key": "env", "Value": "prod"}]})
    s3.put_bucket_policy(
        Bucket="acme-prod-assets",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteBucket", "Resource": "arn:aws:s3:::acme-prod-assets"}]}),
    )

    rds = boto3.client("rds", region_name=REGION)
    rds.create_db_instance(DBInstanceIdentifier="prod-db", DBInstanceClass="db.t3.micro", Engine="postgres",
                           MasterUsername="u", MasterUserPassword="p" * 12, AllocatedStorage=20, BackupRetentionPeriod=7)
    rds.create_db_snapshot(DBInstanceIdentifier="prod-db", DBSnapshotIdentifier="prod-db-manual")

    ddb = boto3.client("dynamodb", region_name=REGION)
    ddb.create_table(TableName="orders-prod", KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                     AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}], BillingMode="PAY_PER_REQUEST")

    ec2 = boto3.client("ec2", region_name=REGION)
    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10)["VolumeId"]
    ec2.create_snapshot(VolumeId=vol)

    kms = boto3.client("kms", region_name=REGION)
    kms.create_key(Description="prod data key")
    return {"key_id": key_id}


@mock_aws
def test_collector_uses_only_allowlisted_reads():
    seeded = _seed()
    snap, log = collect_live(boto3.Session(region_name=REGION), [REGION])

    assert not log.refusals()
    allowed = set(LIVE_OPERATIONS)
    assert set(log.operations()) <= allowed
    assert "iam:GetAccountAuthorizationDetails" in log.operations()

    assert snap.account_id.isdigit()
    role_arn = f"arn:aws:iam::{snap.account_id}:role/agent"
    assert role_arn in snap.iam.roles
    assert {b.name for b in snap.resources.s3_buckets} == {"acme-tfstate-prod", "acme-prod-assets"}
    assets = next(b for b in snap.resources.s3_buckets if b.name == "acme-prod-assets")
    assert assets.versioning == "Enabled" and assets.tags == {"env": "prod"} and assets.policy
    assert [i.identifier for i in snap.resources.rds_instances] == ["prod-db"]
    assert any(s.identifier == "prod-db-manual" for s in snap.resources.rds_snapshots)
    assert [t.name for t in snap.resources.dynamodb_tables] == ["orders-prod"]
    assert len(snap.resources.ebs_volumes) >= 1 and len(snap.resources.ebs_snapshots) >= 1
    assert any(k.description == "prod data key" for k in snap.resources.kms_keys)

    # Access key IDs are only ever stored as fingerprints.
    dumped = json.dumps(snap.to_dict(), default=str)
    assert seeded["key_id"] not in dumped
    assert len(snap.access_key_fingerprints) == 1

    # Round trip through the fixture loader.
    again = snapshot_from_dict(json.loads(dumped), source="roundtrip.json")
    assert set(again.resource_index()) == set(snap.resource_index())


@mock_aws
def test_scan_of_collected_snapshot_finds_admin_risk(tmp_path):
    _seed()
    snap, _ = collect_live(boto3.Session(region_name=REGION), [REGION])
    role_arn = f"arn:aws:iam::{snap.account_id}:role/agent"
    board = run_scan(snap, RunOptions(out_dir=tmp_path, extra_principals=[role_arn], terraform_bin=None))
    actions = {f.action for f in board.verified if f.kind == "destructive_permission"}
    assert "rds:DeleteDBInstance" in actions
    # The bucket policy deny is honoured.
    assert not any(f.action == "s3:DeleteBucket" and f.resource == "arn:aws:s3:::acme-prod-assets" for f in board.verified)
    assert any(f.kind == "state_bucket" and f.verdict == "AT_RISK" for f in board.verified)
    assert (tmp_path / "report.json").is_file()


def test_profile_mapper_uses_sts_through_the_gate(tmp_path, monkeypatch):
    from agent_radius.security.readonly_gate import CallLog
    from agent_radius.snapshot.collector import make_profile_mapper

    cfg = tmp_path / "config"
    cfg.write_text("[profile agent]\nregion = us-east-1\naws_access_key_id = testing\naws_secret_access_key = testing\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(cfg))
    log = CallLog()
    with mock_aws():
        mapper = make_profile_mapper(lambda p: boto3.Session(profile_name=p), REGION, log)
        assert mapper("agent").startswith("arn:aws:")
        assert mapper("no-such-profile") is None
    assert log.operations() == ["sts:GetCallerIdentity"]
