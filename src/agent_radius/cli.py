"""Command line interface: ``agent-radius scan | bench | demo | catalog``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from agent_radius import __version__
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import severity_at_least
from agent_radius.agents.orchestrator import RunOptions, run_scan
from agent_radius.agents.ranking import short_arn
from agent_radius.agents.recon_scan import ReconPaths
from agent_radius.llm.base import ModelConfig
from agent_radius.llm.factory import BACKEND_NAMES, make_backend
from agent_radius.report.render import HEADLINE

DEMO_SCENARIO = "admin-agent-prod-rds-same-account"


def _print_summary(board: Blackboard, out_dir: Path | None, top: int = 10) -> None:
    r = board.report
    s = r["summary"]
    print()
    print(HEADLINE.upper())
    print("=" * len(HEADLINE))
    print(f"Account {r['account_id']}  principals: {', '.join(short_arn(p) for p in r['agent_principals']) or 'none identified'}")
    print(
        f"{s['irreversible']} irreversible / {s['effective_destructive']} destructive actions open on"
        f" {s['resources_exposed']} resources;  backups: {s['at_risk']} AT_RISK, {s['partial']} PARTIAL, {s['survives']} SURVIVE"
    )
    if s.get("conditional"):
        print(f"{s['conditional']} more are possible but conditional (not certain).")
    print()
    for it in r["headline_items"][:top]:
        print(
            f"  {it['rank']:>3}. [irr {it['irreversibility']}] {it['action']:<38} {short_arn(it['resource'])}"
            f"  ({it['certainty']}, {it['severity']})"
        )
    more = len(r["headline_items"]) - top
    if more > 0:
        print(f"       ... and {more} more in the report")
    for b in r["backups"]:
        if b["verdict"] != "SURVIVES":
            print(f"  backup {b['verdict']:<8} {short_arn(b['resource'])}  ({short_arn(b['principal'])})")
    for c in r["credentials"]:
        if c["severity"] in ("high", "critical", "medium"):
            print(f"  credential [{c['severity']}] {c['path']} -> {short_arn(c['principal']) if c['principal'] else 'unmapped'}")
    v = r["verification"]
    wi = r["guardrail"]["what_if"]
    print()
    print(
        f"Verifier: {v['verified']} verified, {v['dropped']} dropped. Deny-policy what-if blocks {wi.get('blocked', 0)}"
        f" of {wi.get('checked', 0)} verified IAM grants. terraform validate: {v['terraform_validate']['status']}"
        + (f" ({v['terraform_validate']['reason']})" if v["terraform_validate"].get("reason") else "")
    )
    if out_dir is not None:
        print(f"Reports: {out_dir / 'report.md'}  {out_dir / 'report.json'}  {out_dir / 'report.html'}")
        print(f"Guardrails (not applied): {out_dir / 'guardrails'}")


def _backend(args: argparse.Namespace) -> Any:
    models = ModelConfig(planner=args.opus_model, summary=args.opus_model, worker=args.sonnet_model)
    return make_backend(args.llm, models=models)


def _live_notice(profile: str, regions: list[str]) -> None:
    from agent_radius.agents.recon_scan import ReconPaths as _RP
    from agent_radius.snapshot.collector import LIVE_OPERATIONS

    print("LIVE MODE (read-only)")
    print(f"Profile {profile!r}, regions {', '.join(regions)}.")
    print("Agent Radius will call ONLY these AWS API operations, each checked by the read-only gate before it is sent:")
    for op in LIVE_OPERATIONS:
        print(f"  {op}")
    print("It never calls Delete*, Put*, Create*, Update*, Modify*, Schedule*, Terminate* or sts:AssumeRole.")
    print("Recon will check these local paths for credential PRESENCE (names and paths only, never values):")
    for p in _RP.from_system().all_candidate_paths():
        print(f"  {p}")
    print()


def cmd_scan(args: argparse.Namespace) -> int:
    out_dir = Path(args.out)
    recon_paths = None
    profile_mapper = None
    fallback: list[str] = []
    if args.fixture:
        from agent_radius.snapshot.fixture import load_fixture

        snapshot = load_fixture(args.fixture)
        if args.recon_home:
            recon_paths = ReconPaths(home=Path(args.recon_home), cwd=Path(args.recon_home), env={})
    else:
        import boto3

        from agent_radius.snapshot.collector import collect_live, make_profile_mapper

        regions = args.region or ["us-east-1"]
        _live_notice(args.profile, regions)
        session = boto3.Session(profile_name=args.profile)
        snapshot, call_log = collect_live(session, regions)
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "snapshot.json").write_text(json.dumps(snapshot.to_dict(), indent=2, default=str) + "\n", encoding="utf-8")
        print(f"Collected snapshot with {len(call_log.operations())} distinct read operations; saved {out_dir / 'snapshot.json'}")
        recon_paths = ReconPaths(home=Path(args.recon_home), cwd=Path(args.recon_home), env={}) if args.recon_home else ReconPaths.from_system()
        profile_mapper = make_profile_mapper(lambda p: boto3.Session(profile_name=p), regions[0], call_log)
        fallback = [snapshot.source.removeprefix("live:")]
    board = run_scan(
        snapshot,
        RunOptions(
            out_dir=out_dir,
            backend=_backend(args),
            recon_paths=recon_paths,
            profile_mapper=profile_mapper,
            extra_principals=args.principal or [],
            fallback_principals=fallback,
            terraform_bin=None if args.no_terraform else "auto",
        ),
    )
    _print_summary(board, out_dir)
    if args.fail_on:
        worst = [f for f in board.verified if f.kind != "guardrail" and severity_at_least(f.severity, args.fail_on)]
        if worst:
            return 3
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from agent_radius.bench.runner import scenarios_dir
    from agent_radius.snapshot.fixture import load_fixture

    fixture = scenarios_dir() / DEMO_SCENARIO / "fixture.json"
    out_dir = Path(args.out)
    print(f"Demo: offline scan of the seeded scenario '{DEMO_SCENARIO}' (no AWS calls, no LLM).")
    board = run_scan(load_fixture(fixture), RunOptions(out_dir=out_dir))
    _print_summary(board, out_dir)
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from agent_radius.bench.runner import run_bench

    results_path = Path(args.results)
    payload = run_bench(
        Path(args.scenarios) if args.scenarios else None,
        Path(args.out) if args.out else None,
        results_path,
    )
    for sc in payload["scenarios"]:
        status = "PASS" if sc["passed"] else "FAIL"
        print(
            f"{status}  {sc['name']:<44} expected {sc['expected_met']}/{sc['expected_total']}"
            f"  must-not violated {sc['must_not_violated']}/{sc['must_not_total']}"
            f"  hallucinations {sc['hallucinations']}  reported {sc['findings_reported']}"
        )
        for failure in sc["failures"]:
            print(f"        - {failure}")
    s = payload["summary"]
    print()
    print(
        f"scenarios {s['passed']}/{s['scenarios']} passed | precision {s['precision']:.3f} | recall {s['recall']:.3f}"
        f" | TP {s['true_positives']} FN {s['false_negatives']} FP {s['false_positives']}"
        f" | hallucinations {s['hallucinations']} | llm {s['llm_backend']}"
    )
    print(f"results written to {results_path}")
    return 0 if s["passed"] == s["scenarios"] else 1


def cmd_catalog(_: argparse.Namespace) -> int:
    from agent_radius.catalog import CATALOG

    for c in sorted(CATALOG, key=lambda c: (-c.irreversibility, c.action)):
        print(f"{c.irreversibility}  {c.action:<42} {c.resource_type:<22} {c.consequence}")
    print(f"\n{len(CATALOG)} actions")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-radius",
        description="Read-only auditor: what could an AI coding agent destroy with the AWS credentials it inherits?",
    )
    parser.add_argument("--version", action="version", version=f"agent-radius {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan a fixture (offline) or a live account (read-only).")
    src = scan.add_mutually_exclusive_group(required=True)
    src.add_argument("--fixture", help="Snapshot JSON file (offline mode).")
    src.add_argument("--profile", help="AWS profile for a live, read-only scan.")
    scan.add_argument("--region", action="append", help="Region to scan (repeatable). Default us-east-1.")
    scan.add_argument("--llm", choices=BACKEND_NAMES, default="none", help="LLM backend for ranking and explanations. Default none.")
    scan.add_argument("--opus-model", default=ModelConfig().planner, help="Model for planning and the executive summary.")
    scan.add_argument("--sonnet-model", default=ModelConfig().worker, help="Model for per-finding ranking and explanations.")
    scan.add_argument("--out", default="agent-radius-out", help="Output directory. Default ./agent-radius-out")
    scan.add_argument("--principal", action="append", help="Treat this principal ARN as an agent identity (repeatable).")
    scan.add_argument("--recon-home", help="Scan this directory as the home directory for local credentials.")
    scan.add_argument("--no-terraform", action="store_true", help="Skip terraform validate even if terraform is installed.")
    scan.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Exit 3 if any finding is at least this severe.")
    scan.set_defaults(func=cmd_scan)

    bench = sub.add_parser("bench", help="Run the offline benchmark (llm none).")
    bench.add_argument("--scenarios", help="Scenario directory. Default: the bundled scenarios.")
    bench.add_argument("--results", default="bench/results.json", help="Where to write results JSON.")
    bench.add_argument("--out", help="Keep per-scenario reports here (default: a temp dir).")
    bench.set_defaults(func=cmd_bench)

    demo = sub.add_parser("demo", help="Run the most striking seeded scenario and print the headline.")
    demo.add_argument("--out", default="agent-radius-out/demo", help="Output directory.")
    demo.set_defaults(func=cmd_demo)

    cat = sub.add_parser("catalog", help="List the destructive-action catalog.")
    cat.set_defaults(func=cmd_catalog)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
