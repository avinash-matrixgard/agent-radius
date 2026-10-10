# IAM semantics in Agent Radius

Agent Radius answers one question offline: would AWS authorise `principal` to call `action` on `resource` in this account? This page states exactly what the evaluator models and, just as important, what it does not. When a feature is not modelled we say how the gap affects results.

The evaluator is `src/agent_radius/iam/evaluator.py`. It returns one of four outcomes plus the matched statements as evidence:

| Outcome | Meaning |
|---|---|
| `ALLOW` | Every required layer grants unconditionally and nothing denies. Reported as certain. |
| `CONDITIONAL` | The request is granted only through statements that carry a `Condition` (or an unresolvable policy variable), or a conditional deny could block it. Reported as possible, never certain. |
| `EXPLICIT_DENY` | An unconditional `Deny` statement matches in an identity policy, permissions boundary, SCP or applicable resource policy. |
| `IMPLICIT_DENY` | Nothing grants it, or a required layer (boundary, SCP level, KMS key policy) does not allow it. |

Every matched statement has a stable evidence id `<policy_ref>#<index>`, for example `managed:arn:aws:iam::aws:policy/AdministratorAccess#0`, `inline:role/agent/StateAccess#0`, `boundary:arn:...#1`, `scp:p-denyrdsdelete#0`, `resource:s3:arn:aws:s3:::bucket#0`, `resource:kms:<key arn>#0`, `resource:backup:<vault arn>#0`.

## Modelled

**Matching**
- `Action` and `NotAction`; `Resource` and `NotResource`.
- Wildcards `*` (any run of characters, including `/` and `:`) and `?` (one character).
- Actions match case-insensitively (service prefix included). Resources match case-sensitively.
- Policy documents as dicts, JSON strings, or URL-encoded JSON (as the raw IAM API returns them).
- A statement with an `Effect` other than `Allow` or `Deny`, or with neither `Action` nor `NotAction`, grants nothing.

**Identity policies**
- Users: inline policies, attached managed policies, and for every group the user is in, the group's inline and attached managed policies.
- Roles: inline and attached managed policies. An STS assumed-role session ARN resolves to its role.
- A managed policy whose document is not in the snapshot contributes nothing and is recorded as a coverage gap. The only AWS managed policy built in is `AdministratorAccess` (its document is a single `Allow * on *`).

**Permissions boundaries**
- If a principal has a boundary, the boundary must also allow (unconditionally for `ALLOW`). A boundary never grants on its own. A `Deny` in a boundary is an explicit deny.
- A missing boundary document is treated as allowing nothing, and recorded as a gap.

**Service control policies** (only when the snapshot includes an `organization` block)
- SCPs are grouped by `level` (for example `root`, `ou:ou-123`, `account`). At every level at least one SCP must allow the action; a deny at any level wins.
- SCPs are ignored for the management account, matching AWS behaviour.
- When SCPs were not collected, results assume no SCP restricts the account and the report lists that as a coverage gap. This can only over-report, never under-report.

**Resource policies (same account)**
- **S3 bucket policies** apply to the bucket ARN and to object ARNs under it.
- **KMS key policies** are the root of trust for a key: a request is allowed only if the key policy grants the principal directly, or delegates to the account (principal is the account root or account id) and an IAM policy also allows. With neither, even `AdministratorAccess` is denied.
- **AWS Backup vault access policies** apply to the vault and to recovery points in it.
- Principal matching: `"*"` or the exact principal ARN is a direct grant. The account root or account id in an `Allow` is delegation only (it does not grant by itself in the same account). In a `Deny`, the account root, account id or `"*"` applies to every principal in the account. `NotPrincipal` applies to everyone not listed. `Service`, `Federated` and `CanonicalUser` principals never match an IAM user or role.
- A same-account resource policy that names an IAM **user** directly is not limited by that user's permissions boundary. For **roles**, the boundary still applies (AWS only exempts grants to the role session ARN).

**Explicit deny wins.** An unconditional deny in any identity policy, boundary, SCP or applicable resource policy returns `EXPLICIT_DENY`.

**Conditions.** Conditions are never evaluated. The rule is: a condition matters only if it can change the outcome.
- A conditional `Allow` that is the only grant on the decisive path makes the result `CONDITIONAL`.
- A conditional `Allow` next to an unconditional `Allow` in the same layer changes nothing: the result is `ALLOW`.
- A conditional `Deny` over an otherwise allowed request makes it `CONDITIONAL`. Over a request nothing grants, it changes nothing: `IMPLICIT_DENY`.
- Policy variables such as `${aws:username}` cannot be resolved offline. They match as `*` and make the statement conditional.

**Cross-account resources.** If the resource ARN carries an account id other than the snapshot's, the evaluator returns `IMPLICIT_DENY` with a note. Cross-account access also needs the other account's resource policy, which v1 does not model, so it never claims such access.

**Two-step paths (used by the Backup agent).** `evaluate(..., ignore_resource_policy=True)` answers "what if the resource policy were removed". The Backup agent combines that with whether the agent can rewrite or delete the policy (`s3:PutBucketPolicy`, `s3:DeleteBucketPolicy`, `backup:PutBackupVaultAccessPolicy`, `backup:DeleteBackupVaultAccessPolicy`) to catch "remove the protection, then delete".

## Not modelled

| Not modelled | Effect on results |
|---|---|
| Condition keys of any kind (MFA, source IP, VPC endpoint, tags, `aws:PrincipalArn`, `aws:RequestedRegion`, ...) | Decisive conditional statements produce `CONDITIONAL`, never a certain answer. |
| Session policies (passed at `AssumeRole` or federation time) | Results describe the role without its session policy; real sessions may be narrower. |
| Assume-role chains (what roles the agent could assume next) | Not followed. A principal that can assume an admin role is only reported for its own permissions, plus `iam:UpdateAssumeRolePolicy` style escalation on roles. |
| Cross-account access (trust policies, other accounts' resource policies, RAM shares) | Never claimed. Copies in other accounts count as surviving. |
| Resource policies other than S3, KMS and AWS Backup (Lambda, SQS, SNS, Secrets Manager, ECR, Glacier, ...) | Identity policies alone decide those requests. |
| KMS grants | Not collected; a grant could add access the report does not show. |
| S3 access points, Block Public Access, ACLs | Ignored. |
| SCP evaluation for service-linked roles (AWS exempts them) | SCPs are applied to every principal in a member account. |
| Resource control policies (RCPs) and declarative policies | Not collected. |
| Object-level prefixes | Object actions are evaluated against `arn:aws:s3:::bucket/*` as a whole. A grant scoped to a prefix is not reported; a deny scoped to a prefix does not protect the whole bucket in the report. |
| Service-specific delete preconditions (a bucket must be empty, a vault must be empty) | Noted in consequences, not enforced. |
