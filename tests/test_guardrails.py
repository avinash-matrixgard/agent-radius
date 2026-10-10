"""Guardrail Terraform rendering and the structural HCL checker."""

from __future__ import annotations

import json

import pytest

from agent_radius.catalog import CATALOG
from agent_radius.guardrails import (
    HclError,
    boundary_policy_document,
    check_hcl,
    deny_policy_document,
    parse_value,
    render_bundle,
    render_value,
)


def test_policy_round_trips_through_hcl_including_policy_variables():
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": "arn:aws:s3:::home/${aws:username}/*",
                       "Condition": {"Bool": {"aws:SecureTransport": False}}, "Sid": 'quote"and\\slash'}],
    }
    text = render_value(policy)
    assert "$${aws:username}" in text
    assert parse_value(text) == policy


def test_bundle_passes_structural_check_and_contains_only_catalog_actions():
    bundle = render_bundle("111122223333", ["rds:DeleteDBInstance", "s3:DeleteObject"], [("role", "agent"), ("user", "ci-admin")],
                           ["arn:aws:rds:us-east-1:111122223333:db:prod-db"], ["acme-tfstate"])
    assert set(bundle.files) == {"versions.tf", "variables.tf", "agent_role.tf", "deny_destructive.tf", "deny_policy.json",
                                 "backup_vault.tf", "state_bucket.tf", "README.md"}
    for name, content in bundle.files.items():
        if name.endswith(".tf"):
            assert check_hcl(content, bundle.policies_by_file.get(name)) == [], name
    catalog = {c.action for c in CATALOG}
    assert set(json.loads(bundle.files["deny_policy.json"])["Statement"][0]["Action"]) <= catalog
    assert 'aws_iam_user_policy_attachment" "deny_user_ci_admin"' in bundle.files["deny_destructive.tf"]
    assert "never runs" in bundle.files["README.md"]


def test_bundle_without_findings_has_no_deny_file():
    bundle = render_bundle("111122223333", [], [], [], [])
    assert "deny_destructive.tf" not in bundle.files and "backup_vault.tf" not in bundle.files
    assert "agent_role.tf" in bundle.files


def test_boundary_denies_every_catalog_action():
    denied = set(boundary_policy_document()["Statement"][1]["Action"])
    assert denied == {c.action for c in CATALOG}


@pytest.mark.parametrize(
    "text,problem",
    [
        ('resource "a" "b" {\n  x = 1\n', "never closed"),
        ('resource "a" "b" {\n  x = "oops\n}\n', "string"),
        ('resource "a" {\n}\n', "labels"),
        ('bogus "a" "b" {\n}\n', "unknown top-level"),
        ('resource "a" "b" {\n  policy = jsonencode({ Foo = "bar" })\n}\n', "Version"),
        ('resource "a" "b" {\n  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Deny", Action = [], Resource = "*" }] })\n}\n', "empty Action"),
        ('resource "a" "b" {\n  policy = jsonencode(var.x)\n}\n', "does not parse"),
    ],
)
def test_checker_catches_broken_hcl(text, problem):
    problems = check_hcl(text)
    assert problems and any(problem in p for p in problems), problems


def test_round_trip_mismatch_is_reported():
    deny = deny_policy_document(["rds:DeleteDBInstance"])
    other = deny_policy_document(["s3:DeleteObject"])
    text = f'resource "aws_iam_policy" "x" {{\n  policy = jsonencode({render_value(other, 1)})\n}}\n'
    assert any("round-trip" in p for p in check_hcl(text, [deny]))


def test_parser_rejects_interpolation():
    with pytest.raises(HclError):
        parse_value('{ a = "${var.x}" }')
