# Security Policy

Agent Radius looks at the most sensitive parts of an AWS account: who can delete what, and where credentials live on a developer machine. Being read-only and never handling secret values is the core contract of the project, not a feature.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Email avinash@matrixgard.com with a minimal reproduction, the version (`agent-radius --version`) or commit, what you expected and what happened, and your view of the impact. Once the repository is public, GitHub private security advisories are also accepted.

Redact real account ids, ARNs, keys and file paths from your report. We aim to acknowledge within 7 days and agree a disclosure timeline (90 days by default) with you.

## The read-only guarantee

Agent Radius never creates, changes or deletes anything in your account, and never runs Terraform `plan` or `apply`.

How that is enforced (`src/agent_radius/security/readonly_gate.py`):

1. **Explicit allowlist.** Every AWS call is made through `ReadOnlyGate`. An operation is allowed only if its exact service and operation name appear in `READ_ONLY_OPERATIONS`. There are no wildcard patterns, so a newly released AWS operation can never slip through by looking like `Get*`.
2. **Mutation verbs refused.** Independently, any operation whose name starts with a state-changing verb (`Delete`, `Put`, `Create`, `Update`, `Modify`, `Schedule`, `Terminate`, `Attach`, `Assume`, `Tag`, `Start`, `Stop`, and more) is refused even if someone adds it to the allowlist by mistake.
3. **Secret readers refused.** Read-shaped calls that return secret material or data contents (`GetSecretValue`, `GetParameter`, `Decrypt`, `GetPasswordData`, `GetObject`, `Scan`, `Query`, `GetSessionToken`, ...) are refused outright.
4. **Checked twice, before signing.** The wrapper checks at method lookup, and a botocore `before-call` hook on the same client checks again for every request that is about to be sent, including paginator pages. A refused call raises `ReadOnlyViolation` and never leaves the process.
5. **Audit.** Every allowed and refused call is logged. Live mode prints the full list of operations it can call before calling any of them.

The live collector declares its operations in `LIVE_OPERATIONS`, and a unit test asserts each one passes the gate. Other tests prove that `Delete*`, `Put*`, `Create*`, `Update*`, `Modify*`, `Schedule*`, `Terminate*` and `sts:AssumeRole` are refused, and that a refused delete leaves the (moto) bucket in place.

For least privilege, run live scans with a role that has only read permissions (for example the AWS managed `SecurityAudit` policy) and name the agent's role with `--principal`. Any operation the scanning role cannot perform is recorded as a coverage gap instead of failing the scan. The gate means Agent Radius would not misuse broader credentials, but you should not have to trust that.

## Secret values never leave the machine, and never reach an LLM

- **Recon reads structure, keeps names.** AWS config and credentials files, MCP configs and agent settings are parsed in memory. For every secret-bearing key, only the key name is recorded; the value is dropped during parsing. The secret access key and session token are never stored in any structure that outlives the parse.
- **Access key IDs become fingerprints.** To map an embedded access key to an IAM user offline, Recon keeps a salted SHA-256 fingerprint (16 hex characters) of the key ID; the live collector does the same for the key IDs returned by `iam:ListAccessKeys`. Raw key IDs are not stored or written.
- **No credential contents are ever printed or written.** Reports show file paths (relative to home) and key names only. Google ADC files are checked for presence, not opened.
- **Backstops.** Every record Recon produces is checked for secret-shaped strings (it raises on a hit). The Verifier drops any finding containing a secret-shaped string. The Reporter scrubs the whole report and refuses to write if anything secret-shaped remains.
- **LLM inputs.** With the optional LLM backends, only verified finding summaries are sent (ids, titles, actions, ARNs, verdicts, consequences, and for credentials only the source type, path and key names). The payload is scrubbed and then checked again; if anything secret-shaped remains, nothing is sent. Raw credential files are never sent. The default backend is `none`, which sends nothing anywhere.

## Testing posture

All tests run offline: `tmp_path` fixtures and moto. An autouse fixture points `HOME`, `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` at temporary paths so no test can read real credentials. LLM backends are tested with fakes only; no test makes a paid API call.

## Out of scope

- Findings are only as complete as the snapshot and the modelled IAM semantics (see docs/IAM_SEMANTICS.md). Absence of a finding is not proof of safety.
- The generated Terraform is a starting point to review, not a drop-in change.
