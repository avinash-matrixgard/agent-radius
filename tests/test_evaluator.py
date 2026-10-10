"""IAM evaluator: one test (at least) per supported rule."""

from __future__ import annotations

import json
import urllib.parse

import pytest

from agent_radius.iam import Evaluator, Outcome, action_matches, resource_matches
from tests.helpers import (
    ACCT,
    ADMIN,
    OTHER,
    R,
    allow,
    deny,
    doc,
    group,
    kms_arn,
    make,
    managed,
    rds_arn,
    role,
    role_arn,
    user,
    user_arn,
)

DB = rds_arn("prod-db")
RES = {"rds_instances": [{"identifier": "prod-db", "arn": DB}]}


def ev(snap):
    return Evaluator(snap)


# ---- matching ------------------------------------------------------------


def test_action_wildcards_and_case_insensitivity():
    assert action_matches("rds:Delete*", "rds:DeleteDBInstance")
    assert action_matches("RDS:delete*", "rds:DeleteDBInstance")
    assert action_matches("rds:Delete?BInstance", "rds:DeleteDBInstance")
    assert not action_matches("rds:Delete?Instance", "rds:DeleteDBInstance")
    assert action_matches("*", "anything:AtAll")
    assert not action_matches("s3:*", "rds:DeleteDBInstance")


def test_resource_matching_is_case_sensitive():
    assert resource_matches("arn:aws:s3:::prod-*", "arn:aws:s3:::prod-data")
    assert not resource_matches("arn:aws:s3:::PROD-*", "arn:aws:s3:::prod-data")
    assert resource_matches("arn:aws:rds:*:*:db:dev-*", "arn:aws:rds:us-east-1:111122223333:db:dev-db")
    assert not resource_matches("arn:aws:rds:*:*:db:dev-*", DB)


# ---- identity policies ----------------------------------------------------


def test_admin_role_is_allowed():
    s = make(roles=[role("agent", attached=[ADMIN])], resources=RES)
    d = ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB)
    assert d.outcome == Outcome.ALLOW
    assert d.evidence_ids == [f"managed:{ADMIN}#0"]


def test_no_policy_is_implicit_deny():
    s = make(roles=[role("agent")], resources=RES)
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.IMPLICIT_DENY


def test_user_inline_group_inline_and_group_managed_policies_count():
    pol = "arn:aws:iam::111122223333:policy/GroupManaged"
    s = make(
        users=[user("dev", inline={"Own": doc(allow("s3:DeleteBucket"))}, groups=["devs"])],
        groups=[group("devs", attached=[pol], inline={"G": doc(allow("rds:DeleteDBInstance"))})],
        policies=[managed(pol, doc(allow("dynamodb:DeleteTable")))],
        resources=RES,
    )
    e = ev(s)
    assert e.evaluate(user_arn("dev"), "s3:DeleteBucket", "arn:aws:s3:::x").outcome == Outcome.ALLOW
    assert e.evaluate(user_arn("dev"), "rds:DeleteDBInstance", DB).outcome == Outcome.ALLOW
    d = e.evaluate(user_arn("dev"), "dynamodb:DeleteTable", "arn:aws:dynamodb:us-east-1:111122223333:table/t")
    assert d.outcome == Outcome.ALLOW
    assert d.evidence_ids == [f"managed:{pol}#0"]


def test_not_action_grants_everything_else():
    s = make(roles=[role("agent", inline={"Dev": doc({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"})})], resources=RES)
    e = ev(s)
    assert e.evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.ALLOW
    assert e.evaluate(role_arn("agent"), "iam:DeleteRole", role_arn("agent")).outcome == Outcome.IMPLICIT_DENY


def test_not_resource():
    s = make(roles=[role("agent", inline={"P": doc({"Effect": "Allow", "Action": "rds:*", "NotResource": [DB]})})], resources=RES)
    e = ev(s)
    assert e.evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.IMPLICIT_DENY
    assert e.evaluate(role_arn("agent"), "rds:DeleteDBInstance", rds_arn("other")).outcome == Outcome.ALLOW


def test_explicit_deny_beats_allow():
    s = make(roles=[role("agent", attached=[ADMIN], inline={"No": doc(deny("rds:Delete*"))})], resources=RES)
    d = ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB)
    assert d.outcome == Outcome.EXPLICIT_DENY
    assert d.evidence_ids == ["inline:role/agent/No#0"]


def test_missing_managed_policy_is_a_gap_not_a_grant():
    s = make(roles=[role("agent", attached=["arn:aws:iam::aws:policy/PowerUserAccess"])], resources=RES)
    d = ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB)
    assert d.outcome == Outcome.IMPLICIT_DENY
    assert any("PowerUserAccess" in g for g in d.gaps)


def test_url_encoded_policy_document_is_parsed():
    encoded = urllib.parse.quote(json.dumps(doc(allow("rds:DeleteDBInstance"))))
    s = make(roles=[role("agent", inline={"Enc": encoded})], resources=RES)
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.ALLOW


def test_assumed_role_session_arn_resolves_to_role():
    s = make(roles=[role("agent", attached=[ADMIN])], resources=RES)
    session = f"arn:aws:sts::{ACCT}:assumed-role/agent/claude-session"
    assert ev(s).evaluate(session, "rds:DeleteDBInstance", DB).outcome == Outcome.ALLOW


def test_unknown_principal_is_implicit_deny():
    s = make(resources=RES)
    assert ev(s).evaluate(role_arn("ghost"), "rds:DeleteDBInstance", DB).outcome == Outcome.IMPLICIT_DENY


def test_cross_account_resource_is_never_claimed():
    s = make(roles=[role("agent", attached=[ADMIN])])
    d = ev(s).evaluate(role_arn("agent"), "ec2:DeleteSnapshot", f"arn:aws:ec2:{R}:{OTHER}:snapshot/snap-1")
    assert d.outcome == Outcome.IMPLICIT_DENY
    assert "cross-account" in d.notes[0]


# ---- conditions ------------------------------------------------------------

MFA = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}


def test_conditional_allow_is_conditional():
    s = make(roles=[role("agent", inline={"P": doc(allow("rds:DeleteDBInstance", Condition=MFA))})], resources=RES)
    d = ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB)
    assert d.outcome == Outcome.CONDITIONAL
    assert d.matched[0].conditional and "aws:MultiFactorAuthPresent" in d.matched[0].why_conditional


def test_conditional_allow_next_to_unconditional_allow_is_allow():
    s = make(roles=[role("agent", attached=[ADMIN], inline={"P": doc(allow("rds:DeleteDBInstance", Condition=MFA))})], resources=RES)
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.ALLOW


def test_conditional_deny_over_allow_is_conditional():
    cond = {"StringNotEquals": {"aws:RequestedRegion": "us-east-1"}}
    s = make(roles=[role("agent", attached=[ADMIN], inline={"D": doc(deny("rds:*", Condition=cond))})], resources=RES)
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.CONDITIONAL


def test_conditional_deny_without_allow_stays_implicit_deny():
    cond = {"Bool": {"aws:SecureTransport": "false"}}
    s = make(roles=[role("agent", inline={"D": doc(deny("rds:*", Condition=cond))})], resources=RES)
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.IMPLICIT_DENY


def test_policy_variable_makes_result_conditional():
    s = make(users=[user("dev", inline={"P": doc(allow("s3:DeleteObject", "arn:aws:s3:::home/${aws:username}/*"))})])
    d = ev(s).evaluate(user_arn("dev"), "s3:DeleteObject", "arn:aws:s3:::home/dev/notes.txt")
    assert d.outcome == Outcome.CONDITIONAL


# ---- permissions boundaries -------------------------------------------------

BOUNDARY = "arn:aws:iam::111122223333:policy/Boundary"


def test_boundary_must_also_allow():
    s = make(
        roles=[role("agent", attached=[ADMIN], boundary=BOUNDARY)],
        policies=[managed(BOUNDARY, doc(allow(["s3:Get*", "s3:List*"])))],
        resources=RES,
    )
    e = ev(s)
    d = e.evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB)
    assert d.outcome == Outcome.IMPLICIT_DENY
    assert any("boundary" in n for n in d.notes)
    assert e.evaluate(role_arn("agent"), "s3:GetObject", "arn:aws:s3:::b/k").outcome == Outcome.ALLOW


def test_boundary_alone_grants_nothing():
    s = make(roles=[role("agent", boundary=BOUNDARY)], policies=[managed(BOUNDARY, doc(allow("*")))], resources=RES)
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.IMPLICIT_DENY


def test_boundary_deny_is_explicit():
    s = make(
        roles=[role("agent", attached=[ADMIN], boundary=BOUNDARY)],
        policies=[managed(BOUNDARY, doc(allow("*"), deny("rds:Delete*")))],
        resources=RES,
    )
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.EXPLICIT_DENY


# ---- SCPs --------------------------------------------------------------------


def _org(*scps, management=False):
    return {"management_account": management, "scps": list(scps)}


FULL = {"id": "p-full", "name": "FullAWSAccess", "level": "root", "document": doc(allow("*"))}


def test_scp_deny_wins():
    s = make(roles=[role("agent", attached=[ADMIN])], resources=RES,
             org=_org(FULL, {"id": "p-d", "level": "root", "document": doc(deny("rds:Delete*"))}))
    d = ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB)
    assert d.outcome == Outcome.EXPLICIT_DENY and d.evidence_ids == ["scp:p-d#0"]


def test_every_scp_level_must_allow():
    ou_only_s3 = {"id": "p-ou", "level": "ou:ou-1", "document": doc(allow("s3:*"))}
    s = make(roles=[role("agent", attached=[ADMIN])], resources=RES, org=_org(FULL, ou_only_s3))
    e = ev(s)
    assert e.evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.IMPLICIT_DENY
    assert e.evaluate(role_arn("agent"), "s3:DeleteBucket", "arn:aws:s3:::b").outcome == Outcome.ALLOW


def test_scps_do_not_apply_to_the_management_account():
    s = make(roles=[role("agent", attached=[ADMIN])], resources=RES,
             org=_org({"id": "p-d", "level": "root", "document": doc(deny("*"))}, management=True))
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.ALLOW


# ---- S3 bucket policies ------------------------------------------------------


def _bucket(policy):
    return {"s3_buckets": [{"name": "media", "policy": policy}]}


def test_bucket_policy_deny_wins_over_admin():
    pol = doc({"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteBucket", "Resource": "arn:aws:s3:::media"})
    s = make(roles=[role("agent", attached=[ADMIN])], resources=_bucket(pol))
    d = ev(s).evaluate(role_arn("agent"), "s3:DeleteBucket", "arn:aws:s3:::media")
    assert d.outcome == Outcome.EXPLICIT_DENY
    assert d.evidence_ids == ["resource:s3:arn:aws:s3:::media#0"]


def test_bucket_policy_naming_the_user_grants_without_identity_policy():
    pol = doc({"Effect": "Allow", "Principal": {"AWS": user_arn("dev")}, "Action": "s3:DeleteObject", "Resource": "arn:aws:s3:::media/*"})
    s = make(users=[user("dev")], resources=_bucket(pol))
    assert ev(s).evaluate(user_arn("dev"), "s3:DeleteObject", "arn:aws:s3:::media/*").outcome == Outcome.ALLOW


def test_bucket_policy_naming_the_account_does_not_grant_by_itself():
    pol = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}, "Action": "s3:*", "Resource": "*"})
    s = make(users=[user("dev")], resources=_bucket(pol))
    assert ev(s).evaluate(user_arn("dev"), "s3:DeleteObject", "arn:aws:s3:::media/*").outcome == Outcome.IMPLICIT_DENY


def test_resource_grant_to_user_bypasses_boundary_but_not_for_roles():
    pol = doc({"Effect": "Allow", "Principal": {"AWS": [user_arn("dev"), role_arn("agent")]}, "Action": "s3:DeleteObject", "Resource": "*"})
    s = make(
        users=[user("dev", boundary=BOUNDARY)],
        roles=[role("agent", boundary=BOUNDARY)],
        policies=[managed(BOUNDARY, doc(allow("s3:Get*")))],
        resources=_bucket(pol),
    )
    e = ev(s)
    assert e.evaluate(user_arn("dev"), "s3:DeleteObject", "arn:aws:s3:::media/*").outcome == Outcome.ALLOW
    assert e.evaluate(role_arn("agent"), "s3:DeleteObject", "arn:aws:s3:::media/*").outcome == Outcome.IMPLICIT_DENY


def test_not_principal_deny_applies_to_everyone_else():
    pol = doc({"Effect": "Deny", "NotPrincipal": {"AWS": role_arn("breakglass")}, "Action": "s3:DeleteObject", "Resource": "*"})
    s = make(roles=[role("agent", attached=[ADMIN]), role("breakglass", attached=[ADMIN])], resources=_bucket(pol))
    e = ev(s)
    assert e.evaluate(role_arn("agent"), "s3:DeleteObject", "arn:aws:s3:::media/*").outcome == Outcome.EXPLICIT_DENY
    assert e.evaluate(role_arn("breakglass"), "s3:DeleteObject", "arn:aws:s3:::media/*").outcome == Outcome.ALLOW


def test_ignore_resource_policy_answers_the_two_step_question():
    pol = doc({"Effect": "Deny", "Principal": "*", "Action": "s3:DeleteObject", "Resource": "*"})
    s = make(roles=[role("agent", attached=[ADMIN])], resources=_bucket(pol))
    e = ev(s)
    assert e.evaluate(role_arn("agent"), "s3:DeleteObject", "arn:aws:s3:::media/*").outcome == Outcome.EXPLICIT_DENY
    d = e.evaluate(role_arn("agent"), "s3:DeleteObject", "arn:aws:s3:::media/*", ignore_resource_policy=True)
    assert d.outcome == Outcome.ALLOW


# ---- KMS key policies --------------------------------------------------------


def _key(policy, kid="k1"):
    return {"kms_keys": [{"key_id": kid, "arn": kms_arn(kid), "policy": policy}]}


ROOT_DELEGATION = doc({"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"}, "Action": "kms:*", "Resource": "*"})


def test_kms_delegation_to_account_lets_iam_decide():
    s = make(roles=[role("agent", attached=[ADMIN]), role("other")], resources=_key(ROOT_DELEGATION))
    e = ev(s)
    assert e.evaluate(role_arn("agent"), "kms:ScheduleKeyDeletion", kms_arn("k1")).outcome == Outcome.ALLOW
    assert e.evaluate(role_arn("other"), "kms:ScheduleKeyDeletion", kms_arn("k1")).outcome == Outcome.IMPLICIT_DENY


def test_kms_without_delegation_blocks_even_admin():
    pol = doc({"Effect": "Allow", "Principal": {"AWS": role_arn("key-admin")}, "Action": "kms:*", "Resource": "*"})
    s = make(roles=[role("agent", attached=[ADMIN]), role("key-admin")], resources=_key(pol))
    e = ev(s)
    d = e.evaluate(role_arn("agent"), "kms:ScheduleKeyDeletion", kms_arn("k1"))
    assert d.outcome == Outcome.IMPLICIT_DENY
    assert any("does not delegate" in n for n in d.notes)
    # The key policy grants key-admin directly, no identity policy needed.
    assert e.evaluate(role_arn("key-admin"), "kms:ScheduleKeyDeletion", kms_arn("k1")).outcome == Outcome.ALLOW


def test_kms_key_policy_deny():
    pol = doc(ROOT_DELEGATION["Statement"][0], {"Effect": "Deny", "Principal": "*", "Action": "kms:ScheduleKeyDeletion", "Resource": "*"})
    s = make(roles=[role("agent", attached=[ADMIN])], resources=_key(pol))
    assert ev(s).evaluate(role_arn("agent"), "kms:ScheduleKeyDeletion", kms_arn("k1")).outcome == Outcome.EXPLICIT_DENY


# ---- Backup vault access policies --------------------------------------------


def test_backup_vault_policy_deny_protects_recovery_points():
    vault_arn = f"arn:aws:backup:{R}:{ACCT}:backup-vault:v"
    rp = f"arn:aws:backup:{R}:{ACCT}:recovery-point:rp-1"
    pol = doc({"Effect": "Deny", "Principal": "*", "Action": "backup:DeleteRecoveryPoint", "Resource": "*"})
    s = make(
        roles=[role("agent", attached=[ADMIN])],
        resources={
            "backup_vaults": [{"name": "v", "arn": vault_arn, "access_policy": pol}],
            "recovery_points": [{"arn": rp, "vault_arn": vault_arn, "source_resource_arn": DB}],
        },
    )
    d = ev(s).evaluate(role_arn("agent"), "backup:DeleteRecoveryPoint", rp)
    assert d.outcome == Outcome.EXPLICIT_DENY
    assert d.evidence_ids == [f"resource:backup:{vault_arn}#0"]


@pytest.mark.parametrize("bad", [{"Effect": "Maybe", "Action": "*", "Resource": "*"}, {"Effect": "Allow", "Resource": "*"}])
def test_malformed_statements_grant_nothing(bad):
    s = make(roles=[role("agent", inline={"Bad": doc(bad)})], resources=RES)
    assert ev(s).evaluate(role_arn("agent"), "rds:DeleteDBInstance", DB).outcome == Outcome.IMPLICIT_DENY
