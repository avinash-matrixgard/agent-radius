# Changelog

All notable changes to this project are listed here. Versions follow semantic versioning.

## 0.1.0 (2026-10-10)

First release.

- Snapshot model of one AWS account, loadable from a fixture or a live read-only collector (34 allowlisted read operations).
- Read-only gate: exact allowlist, mutation-verb and secret-reader refusals, enforced at method lookup and again in a botocore `before-call` hook.
- Offline IAM evaluator: Action, NotAction, Resource, NotResource, wildcards, user, group and role policies, permissions boundaries, SCPs by level, S3 bucket, KMS key and AWS Backup vault policies, explicit deny, CONDITIONAL for decisive conditions.
- Catalog of 66 destructive AWS actions with irreversibility, consequence and category.
- Multi-agent pipeline on a shared blackboard: Planner, Recon, Permissions, Backup, Guardrail, Verifier, Reporter, with an agent trace in `report.json`.
- Recon of local credentials (AWS profiles, `AWS_*` env names, gcloud ADC presence, MCP and agent configs) with no secret values stored or emitted.
- Backup survivability verdicts (SURVIVES, PARTIAL, AT_RISK), including cross-account copies, vault lock modes, Object Lock, PITR and two-step policy-rewrite paths; Terraform state bucket detection.
- Guardrail Terraform (never applied): agent role with permissions boundary, deny policy, cross-account locked vault, state bucket versioning and Object Lock.
- Verifier: anti-hallucination and reproduction checks, deny-policy what-if, structural HCL check, `terraform validate` when installed.
- Optional LLM backends (`anthropic`, `claude-cli`) restricted to planning, ranking and explanation, with schema validation and stripping of unverified ARNs and actions.
- Offline benchmark of 18 scenarios with ground truth (`agent-radius bench`).
- Reports in Markdown, JSON and self-contained HTML.
