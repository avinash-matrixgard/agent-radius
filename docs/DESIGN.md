# Agent Radius design (v1)

## Goal

Answer three questions about one AWS account, without changing anything in it:

1. What could an AI coding agent destroy with the credentials it inherits?
2. Would the backups survive?
3. What guardrail would have prevented it?

Every claim in the output must trace to evidence in the snapshot, and nothing an LLM writes can add a claim.

## Non-negotiables

- **Read-only.** All AWS access goes through `security/readonly_gate.py`. See SECURITY.md.
- **No secret values.** Recon records presence, key names and paths. Access key IDs are kept only as salted SHA-256 fingerprints, for matching to IAM users.
- **Offline by default.** Fixtures, the evaluator, the agents, the bench and the default `none` LLM backend need no network.
- **Never claim certainty you do not have.** Conditions make results CONDITIONAL; unmodelled semantics are listed as gaps.

## Package layout

```
src/agent_radius/
  snapshot/     model.py (dataclasses), fixture.py (JSON loader), collector.py (live, gated)
  security/     readonly_gate.py (allowlist gate), redact.py (secret patterns, scrub)
  iam/          matching.py, policy.py, evaluator.py
  catalog/      actions.py (66 destructive actions)
  agents/       blackboard, findings, tools, base, assess (shared pure logic),
                planner, recon (+ recon_scan), permissions, backup, guardrail,
                verifier, reporter, orchestrator, ranking
  guardrails/   hcl.py (render, parse, structural check), terraform.py (bundle)
  llm/          base, none/anthropic/claude-cli backends, schema, sanitize, advisor
  report/       render.py (markdown, html)
  bench/        runner.py, scenarios/<name>/{fixture.json,truth.json}
  cli.py
```

## Snapshot

One account, one or more regions. IAM keeps the exact shape of `aws iam get-account-authorization-details` (`UserDetailList`, `GroupDetailList`, `RoleDetailList`, `Policies` with default version documents), so a real export drops straight in. Optional `organization` holds SCPs grouped by level. Resources: S3 buckets (versioning, MFA delete, Object Lock, policy, replication, tags, KMS key), RDS instances, clusters and snapshots, DynamoDB tables (deletion protection, PITR, backups), EBS volumes and snapshots, KMS keys (policy, state, manager, origin), AWS Backup vaults (access policy, lock mode, immutability) and recovery points (source resource, account, region). Plus `local_credentials`, `agent_principals`, `profile_principals` and `access_key_fingerprints` for offline identity mapping, and `coverage_gaps`.

`Snapshot.resource_index()` maps every ARN (including `bucket/*` object scopes and `table/T/backup/*`) to a typed `ResourceRef` with an environment class (prod, nonprod, unknown) derived from tags first, then the name.

The live collector calls 34 allowlisted read operations (`LIVE_OPERATIONS`), records any failure as a coverage gap instead of aborting, and derives cross-account copies from completed AWS Backup copy jobs.

## Agents and the blackboard

All agents share one `Blackboard`: the snapshot, the evaluator, the plan, the agent principals, posted findings, verified findings, dropped findings with reasons, guardrail output, verification results and an ordered trace. `post()` refuses a finding without evidence.

Each agent declares a role and the names of the read-only tools it may use (`evaluate`, `list_resources`, `get_resource`, `catalog`, `catalog_entry`, `account_wide_arn`, `principal`, `list_principals`, `local_credentials`). Its `Toolbox` raises if it calls anything else, and counts calls for the trace.

| Agent | Does | Posts |
|---|---|---|
| Planner | Orders resources prod first, then unknown, then non-prod, by type importance; decides which specialists run (Backup is skipped when there are no stateful resources). The LLM may only permute the order. | the plan |
| Recon | In fixture mode reads `local_credentials`; with `ReconPaths` (live mode, tests, bench) scans AWS config and credentials files, `AWS_*` env names, gcloud ADC presence, and MCP or agent configs. Maps credentials to principals by `role_arn`, `source_profile`, STS (live), `profile_principals` or key fingerprint. | `local_credential` |
| Permissions | For each agent principal, each catalog action, each matching resource (or the account-wide ARN for unmodelled types): evaluate, then apply resource protections (deletion protection with or without the companion modify action, Object Lock, MFA delete, vault lock, AWS managed keys, key origin). | `destructive_permission` |
| Backup | For each stateful resource: can the agent destroy the primary and every copy? | `backup_survivability`, `state_bucket` |
| Guardrail | Renders Terraform from what was found. Only catalogued actions can enter the deny list. | `guardrail` |
| Verifier | Existence checks, reproduction, what-if, HCL check, optional `terraform validate`. | drops, verification |
| Reporter | Ranks (by irreversibility, then the advisor's order), explains, writes reports after a final secret scrub. | reports |

Orchestration: Planner, Recon, then Permissions and Backup in parallel threads, then Guardrail, Verifier, Reporter. The evaluator caches are lock protected; findings are posted under a lock; verified output is sorted deterministically.

## Severity

Destructive permissions: start from irreversibility (1 to 3), add 1 for prod, raise privilege escalation to at least 3, subtract 1 when only possible (conditional). 4 or more is critical, 3 high, 2 medium, else low. A grant blocked in practice by a resource setting is low. A wildcard DynamoDB backup grant on a table with no backups today is capped at medium and marked latent.

Backup verdicts: AT_RISK is critical in prod and high elsewhere; PARTIAL is high in prod and medium elsewhere; SURVIVES is info. State buckets: AT_RISK critical, PARTIAL high.

## Survivability model

For a principal and a stateful resource, every path is scored SAFE (0), POSSIBLE (1, conditional) or LOST (2, certain), with OR as max and AND as min.

- **Primary.** RDS: delete (AND modify, when deletion protection is on). DynamoDB: delete table (AND update table, when protected) OR item deletes. S3: delete objects OR a lifecycle expiration rule. EBS: delete volume.
- **Copies.** RDS automated backups (die with the instance by default, or with retention set to 0), manual snapshots, AWS Backup recovery points; DynamoDB PITR (switch off, or delete the system backup kept after a delete), on-demand backups, recovery points; S3 object versions (Object Lock compliance and MFA delete protect them; governance mode needs `s3:BypassGovernanceRetention`), replicas, recovery points; EBS snapshots, recovery points.
- Copies in another account are SAFE. Recovery points in a compliance-mode vault past its cooling-off date are SAFE. A governance-mode or not-yet-immutable lock is only as strong as the agent's inability to remove it.
- Where a resource policy deny protects a copy, the agent may still remove it in two steps (rewrite or delete the policy, then delete). That path is scored too.
- **Verdict.** Primary SAFE, or any copy SAFE: SURVIVES. Primary LOST and every copy LOST (or no copies): AT_RISK. Anything else: PARTIAL.
- If the agent can schedule deletion of the KMS key protecting the resource, a note says same-account copies under that key become unreadable too.

## Verifier

1. **Existence.** Every cited statement id must exist in the snapshot's parsed policies; every cited resource must be in the resource index, a replication destination, or an account-wide catalog ARN; credential ids must be ones Recon produced; the principal must exist; the action must be in the catalog. Any finding with a secret-shaped string is dropped.
2. **Reproduction.** Permission findings are re-evaluated (with protections) and must match outcome, effectiveness, and cite only statements the evaluator matched, including at least one decisive one. Backup and state findings are re-assessed and must match the verdict.
3. **What-if.** The deny policy is attached inline to each agent principal in a copy of the snapshot; every verified destructive permission is re-evaluated, and every backup verdict reassessed. Results land in each finding's `guardrail_what_if`.
4. **Terraform.** The structural checker verifies balanced delimiters, terminated strings, well-formed top-level blocks, and that every `jsonencode(...)` argument parses back to the exact policy rendered. `terraform validate` runs only if Terraform is installed (after `init -backend=false`), else the result is `skipped: terraform not installed`.

## LLM boundary

`llm/advisor.py` is the only caller of a model. Allowed: reorder the plan, rank verified findings by business impact, write explanations and an executive summary. Every response must validate against a JSON schema (`llm/schema.py`); ids not in the verified set are ignored and logged; ARNs and actions not in the verified set are replaced with a marker and logged in `report.json` under `llm.stripped` and in the trace. Inputs are finding summaries only, scrubbed and re-checked for secret shapes before sending. Any backend error falls back to deterministic output. The Anthropic backend uses structured outputs and opts into the server-side refusal fallback; a refusal falls back to deterministic output too.

## Benchmark

`bench/runner.py` loads each scenario, materialises any `setup.local_files` into a temporary home for Recon, runs the full pipeline with the `none` backend, and scores rules: expectations met (TP), expectations missed (FN), must-not rules violated (FP), plus independent hallucination checks and `output_contains` checks over every written file. Benchmarks are regression guards. When one fails, fix the engine, unless the expectation itself is wrong, and say which.

## Planned

- v1.1: MCP server mode, so an agent can query its own blast radius before acting.
- Assume-role chain expansion and cross-account trust analysis.
- More resource types per resource (EKS, ECR, Lambda, EFS, Redshift, OpenSearch) instead of account-wide checks.
- Condition evaluation for common keys (for example aws:PrincipalArn and aws:MultiFactorAuthPresent), so a CONDITIONAL result resolves when the snapshot holds the answer.
- GCP module.
