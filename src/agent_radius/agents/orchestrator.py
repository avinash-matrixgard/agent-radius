"""Orchestrator: Planner -> Recon -> (Permissions || Backup) -> Guardrail -> Verifier -> Reporter."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agent_radius.agents.backup import Backup
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.guardrail import Guardrail
from agent_radius.agents.permissions import Permissions
from agent_radius.agents.planner import Planner
from agent_radius.agents.recon import Recon
from agent_radius.agents.recon_scan import ReconPaths
from agent_radius.agents.reporter import Reporter
from agent_radius.agents.verifier import Verifier
from agent_radius.iam.evaluator import Evaluator
from agent_radius.llm.advisor import Advisor
from agent_radius.llm.none_backend import NoneBackend
from agent_radius.snapshot.model import Snapshot


@dataclass
class RunOptions:
    out_dir: Path | None = None
    backend: Any = field(default_factory=NoneBackend)
    recon_paths: ReconPaths | None = None
    profile_mapper: Callable[[str], str | None] | None = None
    extra_principals: list[str] = field(default_factory=list)
    fallback_principals: list[str] = field(default_factory=list)
    terraform_bin: str | None = "auto"
    parallel: bool = True


def run_scan(snapshot: Snapshot, options: RunOptions | None = None) -> Blackboard:
    opts = options or RunOptions()
    board = Blackboard(snapshot=snapshot, evaluator=Evaluator(snapshot), out_dir=opts.out_dir)
    board.llm["backend"] = getattr(opts.backend, "name", "none")
    advisor = Advisor(opts.backend, log=lambda event, detail: board.log("llm", event, detail))

    planner = Planner(advisor)
    recon = Recon(opts.recon_paths, opts.profile_mapper, opts.extra_principals, opts.fallback_principals)
    permissions = Permissions()
    backup = Backup()
    guardrail = Guardrail()
    verifier = Verifier(terraform_bin=opts.terraform_bin)
    reporter = Reporter(advisor)

    board.log("orchestrator", "phase", "plan")
    planner.execute(board)
    board.log("orchestrator", "phase", "recon")
    recon.execute(board)

    board.log("orchestrator", "phase", "permissions + backup (parallel)" if opts.parallel else "permissions, backup")
    specialists = [permissions]
    if board.plan is None or "backup" in board.plan.specialists:
        specialists.append(backup)
    if opts.parallel and len(specialists) > 1:
        with ThreadPoolExecutor(max_workers=len(specialists), thread_name_prefix="agent-radius") as pool:
            for fut in [pool.submit(a.execute, board) for a in specialists]:
                fut.result()
    else:
        for a in specialists:
            a.execute(board)

    board.log("orchestrator", "phase", "guardrail")
    guardrail.execute(board)
    board.log("orchestrator", "phase", "verifier")
    verifier.execute(board)
    board.log("orchestrator", "phase", "reporter")
    reporter.execute(board)
    board.llm["stripped"] = list(advisor.stripped)
    board.llm["errors"] = list(advisor.errors)
    return board
