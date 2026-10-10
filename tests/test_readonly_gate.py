"""The read-only gate refuses every mutating or secret-reading call, in code, before it is sent."""

from __future__ import annotations

import boto3
import pytest
from moto import mock_aws

from agent_radius.security.readonly_gate import (
    MUTATING_VERB_RE,
    READ_ONLY_OPERATIONS,
    SECRET_READ_OPERATIONS,
    ReadOnlyClient,
    ReadOnlyGate,
    ReadOnlyViolation,
    check_operation,
)
from agent_radius.snapshot.collector import LIVE_OPERATIONS

MUTATING = [
    ("rds", "DeleteDBInstance"),
    ("s3", "DeleteBucket"),
    ("s3", "PutBucketPolicy"),
    ("iam", "CreateAccessKey"),
    ("dynamodb", "UpdateTable"),
    ("rds", "ModifyDBInstance"),
    ("kms", "ScheduleKeyDeletion"),
    ("ec2", "TerminateInstances"),
    ("sts", "AssumeRole"),
    ("iam", "AttachRolePolicy"),
    ("backup", "DeleteRecoveryPoint"),
    ("organizations", "LeaveOrganization"),
]


@pytest.mark.parametrize("service,operation", MUTATING)
def test_mutating_operations_are_refused(service, operation):
    allowed, reason = check_operation(service, operation)
    assert not allowed
    assert operation in reason


@pytest.mark.parametrize(
    "service,operation",
    [("secretsmanager", "GetSecretValue"), ("ssm", "GetParameter"), ("s3", "GetObject"), ("ec2", "GetPasswordData"), ("kms", "Decrypt")],
)
def test_secret_readers_are_refused(service, operation):
    assert not check_operation(service, operation)[0]


def test_unlisted_read_is_refused():
    allowed, reason = check_operation("s3", "GetBucketAcl")
    assert not allowed and "allowlist" in reason


def test_allowlist_is_internally_consistent():
    for service, ops in READ_ONLY_OPERATIONS.items():
        for op in ops:
            assert not MUTATING_VERB_RE.match(op), f"{service}:{op} looks mutating"
            assert op not in SECRET_READ_OPERATIONS
            assert check_operation(service, op)[0]


def test_every_live_operation_passes_the_gate():
    for item in LIVE_OPERATIONS:
        service, _, op = item.partition(":")
        assert check_operation(service, op)[0], item


@mock_aws
def test_wrapped_client_allows_reads_and_refuses_writes():
    raw = boto3.client("s3", region_name="us-east-1")
    raw.create_bucket(Bucket="keep-me")  # test setup through the raw moto client
    gate = ReadOnlyGate(boto3.Session(region_name="us-east-1"))
    s3 = gate.client("s3", region_name="us-east-1")
    assert [b["Name"] for b in s3.list_buckets()["Buckets"]] == ["keep-me"]
    with pytest.raises(ReadOnlyViolation):
        s3.delete_bucket  # noqa: B018 - refused at attribute lookup
    with pytest.raises(ReadOnlyViolation):
        s3.put_bucket_policy(Bucket="keep-me", Policy="{}")
    with pytest.raises(ReadOnlyViolation):
        s3.generate_presigned_url("get_object", Params={"Bucket": "keep-me", "Key": "k"})
    with pytest.raises(ReadOnlyViolation):
        s3.get_paginator("list_object_versions")
    assert raw.head_bucket(Bucket="keep-me")["ResponseMetadata"]["HTTPStatusCode"] == 200
    assert gate.log.operations() == ["s3:ListBuckets"]
    assert {r.operation for r in gate.log.refusals()} >= {"DeleteBucket", "PutBucketPolicy"}


@mock_aws
def test_before_call_hook_blocks_even_the_raw_client():
    session = boto3.Session(region_name="us-east-1")
    raw = session.client("s3", region_name="us-east-1")
    raw.create_bucket(Bucket="keep-me")
    ReadOnlyClient(raw)  # registers the botocore before-call hook on this client
    with pytest.raises(ReadOnlyViolation):
        raw.delete_bucket(Bucket="keep-me")
    # The request never left: the bucket is still there.
    other = boto3.client("s3", region_name="us-east-1")
    assert "keep-me" in [b["Name"] for b in other.list_buckets()["Buckets"]]


@mock_aws
def test_assume_role_and_unknown_services_are_refused():
    gate = ReadOnlyGate(boto3.Session(region_name="us-east-1"))
    sts = gate.client("sts", region_name="us-east-1")
    assert sts.get_caller_identity()["Account"]
    with pytest.raises(ReadOnlyViolation):
        sts.assume_role(RoleArn="arn:aws:iam::123456789012:role/x", RoleSessionName="x")
    with pytest.raises(ReadOnlyViolation):
        gate.client("secretsmanager", region_name="us-east-1")
