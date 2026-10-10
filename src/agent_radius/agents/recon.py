"""Recon: finds the credentials an agent process would inherit and maps them
to IAM principals. Never reads or emits secret values."""

from __future__ import annotations

import re
from collections.abc import Callable

from agent_radius.agents.base import Agent
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import Evidence, Finding
from agent_radius.agents.ranking import short_arn
from agent_radius.agents.recon_scan import ReconPaths, scan_local
from agent_radius.snapshot.model import LocalCredential

ProfileMapper = Callable[[str], "str | None"]


def credential_severity(c: LocalCredential) -> str:
    if c.source_type == "gcloud_adc":
        return "info"
    if c.has_static_keys and c.source_type in ("mcp_config", "agent_config"):
        return "high"
    if c.has_static_keys:
        return "medium"
    return "low"


class Recon(Agent):
    name = "recon"
    role = "Discovers credentials an agent process would inherit and maps them to principals."
    tools = frozenset({"local_credentials", "principal", "list_principals"})

    def __init__(
        self,
        paths: ReconPaths | None = None,
        profile_mapper: ProfileMapper | None = None,
        extra_principals: list[str] | None = None,
        fallback_principals: list[str] | None = None,
    ) -> None:
        self.paths = paths
        self.profile_mapper = profile_mapper
        self.extra_principals = list(extra_principals or [])
        self.fallback_principals = list(fallback_principals or [])

    def run(self, board: Blackboard) -> None:
        tb = self.toolbox(board)
        snap = board.snapshot
        fingerprints: dict[str, str] = {}
        scanned = False
        if self.paths is not None:
            result = scan_local(self.paths)
            creds = result.credentials
            fingerprints = result.fingerprints
            scanned = True
            board.log(self.name, "note", f"scanned {len(result.scanned)} local files; {len(creds)} credential sources")
            for err in result.errors:
                board.log(self.name, "note", err)
        else:
            creds = [LocalCredential(**c.__dict__) for c in tb.local_credentials()]
            board.log(self.name, "note", f"using {len(creds)} credential records from the snapshot (no local scan)")

        by_profile: dict[str, str] = {}
        for c in creds:
            self._map(c, fingerprints, snap.profile_principals, snap.access_key_fingerprints)
            if c.principal_arn and c.profile_name:
                by_profile.setdefault(c.profile_name, c.principal_arn)
        # Profiles that chain from another profile through source_profile.
        for c in creds:
            if c.principal_arn is None:
                m = re.search(r"source_profile=([^;\s]+)", c.detail)
                if m and m.group(1) in by_profile:
                    c.principal_arn = by_profile[m.group(1)]
                    c.mapped_via = "source_profile"
            if c.principal_arn is None and c.profile_name in by_profile:
                c.principal_arn = by_profile[c.profile_name]
                c.mapped_via = "same_profile"

        principals: set[str] = set()
        for c in creds:
            if c.principal_arn:
                p = tb.principal(c.principal_arn)
                if p is not None:
                    c.principal_arn = p.arn
                    principals.add(p.arn)
                else:
                    board.log(self.name, "note", f"{c.id} maps to {c.principal_arn}, which is not in the snapshot")
        for arn in list(snap.agent_principals) + self.extra_principals:
            p = tb.principal(arn)
            if p is None:
                board.log(self.name, "note", f"declared agent principal {arn} is not in the snapshot; ignored")
                continue
            principals.add(p.arn)
        if not principals and self.fallback_principals:
            for arn in self.fallback_principals:
                p = tb.principal(arn)
                if p is not None:
                    principals.add(p.arn)
            board.log(self.name, "note", "no local credential mapped to a principal; using the scanning identity as the agent identity")
        board.credentials = creds
        board.agent_principals = sorted(principals)
        if not principals:
            board.log(self.name, "note", "no agent principal identified; pass --principal ARN to name one")

        for c in creds:
            evidence = [Evidence("credential", c.id, c.path)]
            if not scanned:
                evidence.append(Evidence("fixture", snap.source, "local_credentials"))
            what = "Static AWS keys" if c.has_static_keys else "AWS credentials reference"
            if c.source_type == "gcloud_adc":
                what = "Google application default credentials"
            where = f"{c.path}" + (f" ({c.detail})" if c.detail and c.source_type in ("mcp_config", "agent_config") else "")
            target = f" map to {short_arn(c.principal_arn)}" if c.principal_arn else " (principal not mapped)"
            title = f"{what} in {where}{target}"
            board.post(
                self.name,
                Finding(
                    kind="local_credential",
                    agent=self.name,
                    title=title,
                    severity=credential_severity(c),
                    principal=c.principal_arn,
                    evidence=evidence,
                    data={
                        "id_salt": c.id,
                        "credential_id": c.id,
                        "source_type": c.source_type,
                        "path": c.path,
                        "profile_name": c.profile_name,
                        "key_names": list(c.key_names),
                        "has_static_keys": c.has_static_keys,
                        "mapped_via": c.mapped_via,
                        "detail": c.detail,
                    },
                ),
            )
        board.log(self.name, "tool_calls", str(dict(tb.calls)))

    def _map(
        self,
        c: LocalCredential,
        fingerprints: dict[str, str],
        profile_map: dict[str, str],
        fp_map: dict[str, str],
    ) -> None:
        if c.principal_arn:
            c.mapped_via = c.mapped_via or "fixture"
            return
        fp = fingerprints.get(c.id)
        if fp and fp in fp_map:
            c.principal_arn = fp_map[fp]
            c.mapped_via = "key_fingerprint"
            return
        if c.profile_name:
            if self.profile_mapper is not None:
                arn = self.profile_mapper(c.profile_name)
                if arn:
                    c.principal_arn = arn
                    c.mapped_via = "sts"
                    return
            if c.profile_name in profile_map:
                c.principal_arn = profile_map[c.profile_name]
                c.mapped_via = "profile_map"
