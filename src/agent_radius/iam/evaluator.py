"""Offline IAM authorization evaluator.

``Evaluator.evaluate(principal_arn, action, resource_arn)`` answers one
question for one account: would AWS authorise this request? It implements the
same-account subset of the AWS policy evaluation logic:

* identity policies: user inline + attached managed + every group's inline
  and attached managed; role inline + attached managed;
* Action / NotAction, Resource / NotResource, ``*`` and ``?`` wildcards,
  case-insensitive actions;
* permissions boundaries (must also allow);
* service control policies when present (every level must allow; deny wins);
* same-account resource policies: S3 bucket policy, KMS key policy (must grant
  directly or delegate to the account), AWS Backup vault access policy;
* explicit deny anywhere wins.

Conditions are never evaluated. If a statement that could change the outcome
carries a Condition (or a policy variable), the result is CONDITIONAL. See
docs/IAM_SEMANTICS.md for everything this does not model.
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Any

from agent_radius.iam.matching import action_matches, has_policy_variable, resource_matches
from agent_radius.iam.policy import Statement, parse_policy
from agent_radius.snapshot.model import Principal, Snapshot


class Outcome(str, enum.Enum):
    ALLOW = "ALLOW"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    IMPLICIT_DENY = "IMPLICIT_DENY"
    CONDITIONAL = "CONDITIONAL"

    @property
    def permits(self) -> bool:
        """True when the action is (possibly) permitted."""
        return self in (Outcome.ALLOW, Outcome.CONDITIONAL)


# Grant strength inside one layer.
NONE, COND, FULL = 0, 1, 2


@dataclass
class MatchedStatement:
    ref: str
    policy_type: str
    policy_ref: str
    sid: str | None
    effect: str
    conditional: bool
    why_conditional: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ref": self.ref,
            "policy_type": self.policy_type,
            "policy_ref": self.policy_ref,
            "sid": self.sid,
            "effect": self.effect,
            "conditional": self.conditional,
            "why_conditional": self.why_conditional,
        }


@dataclass
class Decision:
    outcome: Outcome
    principal_arn: str
    action: str
    resource_arn: str
    matched: list[MatchedStatement] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

    @property
    def evidence_ids(self) -> list[str]:
        return [m.ref for m in self.matched]

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "principal": self.principal_arn,
            "action": self.action,
            "resource": self.resource_arn,
            "matched": [m.to_dict() for m in self.matched],
            "notes": list(self.notes),
            "gaps": list(self.gaps),
        }


@dataclass
class _Layer:
    allow_full: list[MatchedStatement] = field(default_factory=list)
    allow_cond: list[MatchedStatement] = field(default_factory=list)
    deny_full: list[MatchedStatement] = field(default_factory=list)
    deny_cond: list[MatchedStatement] = field(default_factory=list)

    @property
    def grant(self) -> int:
        if self.allow_full:
            return FULL
        if self.allow_cond:
            return COND
        return NONE

    def extend(self, other: _Layer) -> None:
        self.allow_full += other.allow_full
        self.allow_cond += other.allow_cond
        self.deny_full += other.deny_full
        self.deny_cond += other.deny_cond

    def all(self) -> list[MatchedStatement]:
        return self.deny_full + self.deny_cond + self.allow_full + self.allow_cond


def _statement_applies(st: Statement, action: str, resource: str) -> tuple[bool, str | None]:
    """Does ``st`` cover ``action`` on ``resource``? Returns (applies, why_conditional)."""
    if st.actions is not None:
        if not any(action_matches(p, action) for p in st.actions):
            return False, None
    elif st.not_actions is not None:
        if any(action_matches(p, action) for p in st.not_actions):
            return False, None
    else:
        return False, None

    why: str | None = None
    if st.resources is not None:
        hits = [p for p in st.resources if resource_matches(p, resource)]
        if not hits:
            return False, None
        if all(has_policy_variable(p) for p in hits):
            why = "resource uses a policy variable that cannot be resolved offline"
    elif st.not_resources is not None:
        hits = [p for p in st.not_resources if resource_matches(p, resource)]
        if hits:
            if all(has_policy_variable(p) for p in hits):
                why = "NotResource uses a policy variable that cannot be resolved offline"
            else:
                return False, None
    else:
        return False, None

    if st.has_condition:
        keys = sorted(
            f"{op}:{key}" for op, block in (st.condition or {}).items() for key in (block or {})
        )
        why = "condition " + ", ".join(keys) if keys else "condition block"
    return True, why


def _principal_values(principal: Any) -> list[str]:
    if principal is None:
        return []
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        values: list[str] = []
        for key, val in principal.items():
            if key != "AWS":
                # Service / Federated / CanonicalUser principals never match an IAM user or role.
                continue
            values += [val] if isinstance(val, str) else list(val)
        return values
    if isinstance(principal, str):
        return [principal]
    return []


def _arn_account(arn: str) -> str | None:
    parts = arn.split(":")
    if len(parts) >= 6 and parts[0] == "arn" and len(parts[4]) == 12 and parts[4].isdigit():
        return parts[4]
    return None


class Evaluator:
    """Evaluates requests against one immutable Snapshot. Thread safe."""

    def __init__(self, snapshot: Snapshot) -> None:
        self.snapshot = snapshot
        self._lock = threading.Lock()
        self._identity_cache: dict[str, tuple[list[Statement], list[str]]] = {}
        self._boundary_cache: dict[str, list[Statement] | None] = {}
        self._resource_cache: dict[str, tuple[str | None, list[Statement]]] = {}
        self._scp_levels: dict[str, list[Statement]] | None = None
        self._scp_built = False

    # ---- statement gathering -------------------------------------------

    def identity_statements(self, principal: Principal) -> tuple[list[Statement], list[str]]:
        with self._lock:
            cached = self._identity_cache.get(principal.arn)
        if cached is not None:
            return cached
        iam = self.snapshot.iam
        stmts: list[Statement] = []
        gaps: list[str] = []
        kind = principal.kind
        for pol in principal.inline_policies:
            stmts += parse_policy(pol.document, f"inline:{kind}/{principal.name}/{pol.name}", "identity")
        for arn in principal.attached_policy_arns:
            doc = iam.managed_document(arn)
            if doc is None:
                gaps.append(f"managed policy {arn} is attached but its document is not in the snapshot")
                continue
            stmts += parse_policy(doc, f"managed:{arn}", "identity")
        for gname in principal.group_names:
            group = iam.groups.get(gname)
            if group is None:
                gaps.append(f"group {gname} is referenced but not in the snapshot")
                continue
            for pol in group.inline_policies:
                stmts += parse_policy(pol.document, f"inline:group/{group.name}/{pol.name}", "identity")
            for arn in group.attached_policy_arns:
                doc = iam.managed_document(arn)
                if doc is None:
                    gaps.append(f"managed policy {arn} (via group {gname}) is not in the snapshot")
                    continue
                stmts += parse_policy(doc, f"managed:{arn}", "identity")
        result = (stmts, gaps)
        with self._lock:
            self._identity_cache[principal.arn] = result
        return result

    def boundary_statements(self, principal: Principal) -> tuple[list[Statement] | None, list[str]]:
        arn = principal.permissions_boundary_arn
        if not arn:
            return None, []
        doc = self.snapshot.iam.managed_document(arn)
        if doc is None:
            return [], [f"permissions boundary {arn} is not in the snapshot; treated as allowing nothing"]
        return parse_policy(doc, f"boundary:{arn}", "boundary"), []

    def scp_levels(self) -> dict[str, list[Statement]] | None:
        with self._lock:
            if self._scp_built:
                return self._scp_levels
        org = self.snapshot.organization
        levels: dict[str, list[Statement]] | None = None
        if org is not None and org.scps and not org.management_account:
            levels = {}
            for scp in org.scps:
                levels.setdefault(scp.level, [])
                levels[scp.level] += parse_policy(scp.document, f"scp:{scp.id}", "scp")
        with self._lock:
            self._scp_levels = levels
            self._scp_built = True
        return levels

    def resource_policy(self, resource_arn: str) -> tuple[str | None, list[Statement]]:
        """Return (kind, statements) for the resource policy governing ``resource_arn``."""
        with self._lock:
            cached = self._resource_cache.get(resource_arn)
        if cached is not None:
            return cached
        snap = self.snapshot
        result: tuple[str | None, list[Statement]] = (None, [])
        bucket = snap.bucket_for_arn(resource_arn)
        if bucket is not None:
            result = ("s3", parse_policy(bucket.policy, f"resource:s3:{bucket.arn}", "resource"))
        elif resource_arn.startswith("arn:aws:kms:"):
            key = snap.kms_key(resource_arn)
            if key is not None:
                result = ("kms", parse_policy(key.policy, f"resource:kms:{key.arn}", "resource"))
        elif resource_arn.startswith("arn:aws:backup:"):
            vault = snap.vault_for_arn(resource_arn)
            if vault is not None:
                result = ("backup", parse_policy(vault.access_policy, f"resource:backup:{vault.arn}", "resource"))
        with self._lock:
            self._resource_cache[resource_arn] = result
        return result

    # ---- principal matching for resource policies -----------------------

    def _principal_relation(self, st: Statement, principal_arn: str) -> str | None:
        """How a resource policy statement names our principal.

        Returns "direct" (names the ARN or "*"), "account" (names this
        account), or None (does not apply to the principal).
        """
        acct = self.snapshot.account_id
        root = self.snapshot.root_arn
        if st.not_principal is not None:
            excluded = _principal_values(st.not_principal)
            if principal_arn in excluded or "*" in excluded:
                return None
            if root in excluded or acct in excluded:
                return None
            return "direct"
        values = _principal_values(st.principal)
        if not values:
            return None
        if "*" in values or principal_arn in values:
            return "direct"
        if root in values or acct in values:
            return "account"
        return None

    # ---- the evaluation ---------------------------------------------------

    def _layer(self, stmts: list[Statement], action: str, resource: str) -> _Layer:
        layer = _Layer()
        for st in stmts:
            applies, why = _statement_applies(st, action, resource)
            if not applies:
                continue
            m = MatchedStatement(st.ref, st.policy_type, st.policy_ref, st.sid, st.effect, why is not None, why)
            if st.effect == "Deny":
                (layer.deny_cond if why else layer.deny_full).append(m)
            else:
                (layer.allow_cond if why else layer.allow_full).append(m)
        return layer

    def evaluate(self, principal_arn: str, action: str, resource_arn: str, ignore_resource_policy: bool = False) -> Decision:
        """Evaluate one request. ``ignore_resource_policy`` answers "what if the
        resource policy were removed?", used for two-step attack paths."""
        snap = self.snapshot
        principal = snap.iam.principal(principal_arn)
        if principal is None:
            return Decision(
                Outcome.IMPLICIT_DENY,
                principal_arn,
                action,
                resource_arn,
                notes=["principal is not in the snapshot"],
                gaps=[f"unknown principal {principal_arn}"],
            )

        notes: list[str] = []
        gaps: list[str] = []
        evidence = _Layer()

        resource_account = _arn_account(resource_arn)
        if resource_account and resource_account != snap.account_id:
            # Cross-account access needs the other account's resource policy
            # too. v1 does not model it, so it never claims such access.
            return Decision(
                Outcome.IMPLICIT_DENY,
                principal.arn,
                action,
                resource_arn,
                notes=[f"resource is in account {resource_account}; cross-account access is not modelled"],
                gaps=[f"cross-account access to account {resource_account} not evaluated"],
            )

        identity_stmts, id_gaps = self.identity_statements(principal)
        gaps += id_gaps
        identity = self._layer(identity_stmts, action, resource_arn)
        evidence.extend(identity)

        boundary_stmts, b_gaps = self.boundary_statements(principal)
        gaps += b_gaps
        boundary: _Layer | None = None
        if boundary_stmts is not None:
            boundary = self._layer(boundary_stmts, action, resource_arn)
            evidence.extend(boundary)

        scp_layers: dict[str, _Layer] = {}
        levels = self.scp_levels()
        if levels:
            for level, stmts in levels.items():
                scp_layers[level] = self._layer(stmts, action, resource_arn)
                evidence.extend(scp_layers[level])

        # Resource policy: split statements by how they name the principal.
        rkind, rstmts = self.resource_policy(resource_arn)
        if ignore_resource_policy:
            notes.append("evaluated as if the resource policy were removed")
            rstmts = []
            if rkind == "kms":
                rkind = None
        res_direct = _Layer()
        res_account = _Layer()
        res_deny_applies = _Layer()
        for st in rstmts:
            relation = self._principal_relation(st, principal.arn)
            if relation is None:
                continue
            single = self._layer([st], action, resource_arn)
            if st.effect == "Deny":
                # A deny naming the account applies to every principal in it.
                res_deny_applies.extend(single)
            elif relation == "direct":
                res_direct.extend(single)
            else:
                res_account.extend(single)
        evidence.extend(res_deny_applies)
        evidence.extend(res_direct)
        evidence.extend(res_account)

        # 1. Explicit deny anywhere wins.
        deny_full = identity.deny_full + res_deny_applies.deny_full
        deny_cond = identity.deny_cond + res_deny_applies.deny_cond
        if boundary is not None:
            deny_full += boundary.deny_full
            deny_cond += boundary.deny_cond
        for layer in scp_layers.values():
            deny_full += layer.deny_full
            deny_cond += layer.deny_cond
        if deny_full:
            return Decision(Outcome.EXPLICIT_DENY, principal.arn, action, resource_arn, deny_full, notes, gaps)

        # 2. Grants.
        boundary_grant = boundary.grant if boundary is not None else FULL
        if boundary is not None and boundary.grant == NONE:
            notes.append("permissions boundary does not allow this action")

        if rkind == "kms":
            # The key policy is the root of trust for a KMS key. IAM policies
            # only count when the key policy delegates to the account.
            via_iam = min(identity.grant, res_account.grant)
            if res_account.grant == NONE:
                notes.append("KMS key policy does not delegate this action to the account, so IAM policies cannot grant it")
            via_key = res_direct.grant
            if via_iam == NONE and via_key == NONE:
                notes.append("KMS key policy does not grant this principal")
        else:
            via_iam = identity.grant
            via_key = res_direct.grant  # same-account resource policy grant naming the principal
        if identity.grant == NONE and via_key == NONE:
            notes.append("no identity or resource policy allows this action")

        eff_iam = min(via_iam, boundary_grant)
        # A resource policy naming an IAM user directly is not limited by the
        # user's boundary. For roles the boundary still applies.
        eff_direct = via_key if principal.kind == "user" else min(via_key, boundary_grant)
        grant = max(eff_iam, eff_direct)

        scp_grant = FULL
        for level, layer in scp_layers.items():
            if layer.grant == NONE:
                notes.append(f"no service control policy at level '{level}' allows this action")
            scp_grant = min(scp_grant, layer.grant)
        grant = min(grant, scp_grant)

        matched = evidence.all()
        if grant == NONE:
            return Decision(Outcome.IMPLICIT_DENY, principal.arn, action, resource_arn, matched, notes, gaps)
        if deny_cond:
            notes.append("a conditional explicit deny may block this request")
            return Decision(Outcome.CONDITIONAL, principal.arn, action, resource_arn, matched, notes, gaps)
        if grant == COND:
            notes.append("every grant on the decisive path carries a condition")
            return Decision(Outcome.CONDITIONAL, principal.arn, action, resource_arn, matched, notes, gaps)
        return Decision(Outcome.ALLOW, principal.arn, action, resource_arn, matched, notes, gaps)
