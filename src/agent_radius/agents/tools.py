"""Read-only tools the agents call. Each agent gets a toolbox restricted to
its declared tool names, and every call is counted for the agent trace."""

from __future__ import annotations

from collections import Counter
from typing import Any

from agent_radius.catalog import CATALOG, CatalogAction, account_wide_arn, by_action
from agent_radius.iam.evaluator import Decision, Evaluator
from agent_radius.snapshot.model import ResourceRef, Snapshot

ALL_TOOLS = frozenset(
    {
        "evaluate",
        "list_resources",
        "get_resource",
        "catalog",
        "catalog_entry",
        "account_wide_arn",
        "principal",
        "list_principals",
        "local_credentials",
    }
)


class ToolNotGranted(PermissionError):
    pass


class Toolbox:
    def __init__(self, snapshot: Snapshot, evaluator: Evaluator, granted: frozenset[str]) -> None:
        unknown = granted - ALL_TOOLS
        if unknown:
            raise ValueError(f"unknown tools: {sorted(unknown)}")
        self._snapshot = snapshot
        self._evaluator = evaluator
        self._granted = granted
        self.calls: Counter[str] = Counter()

    def _use(self, name: str) -> None:
        if name not in self._granted:
            raise ToolNotGranted(f"tool {name!r} is not granted to this agent")
        self.calls[name] += 1

    # ---- tools ------------------------------------------------------------

    def evaluate(self, principal: str, action: str, resource: str, ignore_resource_policy: bool = False) -> Decision:
        self._use("evaluate")
        return self._evaluator.evaluate(principal, action, resource, ignore_resource_policy=ignore_resource_policy)

    def list_resources(self, resource_type: str) -> list[ResourceRef]:
        self._use("list_resources")
        return self._snapshot.resources_of_type(resource_type)

    def get_resource(self, arn: str) -> ResourceRef | None:
        self._use("get_resource")
        return self._snapshot.resource(arn)

    def catalog(self) -> tuple[CatalogAction, ...]:
        self._use("catalog")
        return CATALOG

    def catalog_entry(self, action: str) -> CatalogAction | None:
        self._use("catalog_entry")
        return by_action(action)

    def account_wide_arn(self, entry: CatalogAction) -> str:
        self._use("account_wide_arn")
        return account_wide_arn(entry, self._snapshot.account_id, self._snapshot.region)

    def principal(self, arn: str) -> Any:
        self._use("principal")
        return self._snapshot.iam.principal(arn)

    def list_principals(self) -> list[str]:
        self._use("list_principals")
        return sorted(self._snapshot.principal_arns())

    def local_credentials(self) -> list[Any]:
        self._use("local_credentials")
        return list(self._snapshot.local_credentials)

    @property
    def snapshot(self) -> Snapshot:
        # Read access for metadata such as account id and region.
        return self._snapshot
