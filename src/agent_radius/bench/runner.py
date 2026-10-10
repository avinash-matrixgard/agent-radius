"""Benchmark runner.

Each scenario is a directory with ``fixture.json`` (a snapshot) and
``truth.json``::

    {
      "description": "...",
      "setup": {"local_files": {"relative/path": "content"}, "env": {...}},
      "expect":   [ {matcher}, ... ],   # each must match at least one reported finding
      "must_not": [ {matcher}, ... ]    # none may match any reported finding
    }

Matcher keys: kind, action, resource, resource_contains, principal_contains,
outcome, verdict, certainty, severity, severity_at_least, effective,
blocked_by_guardrail, source_type, path_contains. A must_not matcher may
instead be ``{"output_contains": "text"}``, checked against every file the
run wrote.

Scoring (rule level): TP = expectations met, FN = expectations missed,
FP = must_not rules violated. Precision = TP/(TP+FP), recall = TP/(TP+FN).
Hallucinations = reported findings naming a principal, action or resource
that does not exist in the snapshot or catalog (checked independently of
the Verifier). Every run uses the offline ``none`` LLM backend.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from agent_radius.agents.findings import Finding, severity_at_least
from agent_radius.agents.orchestrator import RunOptions, run_scan
from agent_radius.agents.recon_scan import ReconPaths
from agent_radius.catalog import CATALOG, account_wide_arn, by_action
from agent_radius.llm.none_backend import NoneBackend
from agent_radius.snapshot.fixture import load_fixture
from agent_radius.snapshot.model import Snapshot


def scenarios_dir() -> Path:
    return Path(__file__).parent / "scenarios"


@dataclass
class ScenarioResult:
    name: str
    passed: bool
    expected_total: int
    expected_met: int
    must_not_total: int
    must_not_violated: int
    hallucinations: int
    verifier_dropped: int
    findings_reported: int
    failures: list[str] = field(default_factory=list)


MATCHER_KEYS = {
    "kind", "action", "resource", "resource_contains", "principal_contains", "outcome", "verdict",
    "certainty", "severity", "severity_at_least", "effective", "blocked_by_guardrail", "source_type",
    "path_contains", "description",
}


def _matches(m: dict[str, Any], f: Finding) -> bool:
    unknown = set(m) - MATCHER_KEYS
    if unknown:
        raise ValueError(f"unknown matcher keys {sorted(unknown)}")
    for key, want in m.items():
        if key == "kind" and f.kind != want:
            return False
        if key == "action" and (f.action or "").lower() != want.lower():
            return False
        if key == "resource" and f.resource != want:
            return False
        if key == "resource_contains" and want not in (f.resource or ""):
            return False
        if key == "principal_contains" and want not in (f.principal or ""):
            return False
        if key in ("outcome", "verdict", "certainty", "severity") and getattr(f, key) != want:
            return False
        if key == "severity_at_least" and not severity_at_least(f.severity, want):
            return False
        if key == "effective" and f.effective != want:
            return False
        if key == "blocked_by_guardrail" and f.data.get("guardrail_what_if", {}).get("blocked") != want:
            return False
        if key == "source_type" and f.data.get("source_type") != want:
            return False
        if key == "path_contains" and want not in (f.data.get("path") or ""):
            return False
        if key == "description":
            continue
    return True


def _hallucinations(snap: Snapshot, findings: list[Finding]) -> list[str]:
    """Independent existence check, deliberately not reusing Verifier code."""
    principals = set(snap.iam.users) | set(snap.iam.roles)
    resources: set[str] = set()
    r = snap.resources
    for b in r.s3_buckets:
        resources |= {f"arn:aws:s3:::{b.name}", f"arn:aws:s3:::{b.name}/*"}
        resources |= {rule.destination_bucket_arn for rule in b.replication}
    for coll in (r.rds_instances, r.rds_clusters, r.rds_snapshots, r.ebs_volumes, r.ebs_snapshots, r.kms_keys, r.backup_vaults, r.recovery_points):
        resources |= {x.arn for x in coll}
    for t in r.dynamodb_tables:
        resources |= {t.arn, f"{t.arn}/backup/*"} | {bk.arn for bk in t.backups}
    resources |= principals
    resources |= {account_wide_arn(c, snap.account_id, snap.region) for c in CATALOG if not c.modelled}
    bad = []
    for f in findings:
        if f.principal and f.principal not in principals:
            bad.append(f"{f.id}: unknown principal {f.principal}")
        if f.action and by_action(f.action) is None:
            bad.append(f"{f.id}: unknown action {f.action}")
        if f.resource and f.resource not in resources:
            bad.append(f"{f.id}: unknown resource {f.resource}")
    return bad


def _materialise(setup: dict[str, Any], root: Path) -> ReconPaths | None:
    files = setup.get("local_files")
    if not files and not setup.get("env"):
        return None
    home = root / "home"
    cwd = root / "project"
    home.mkdir(parents=True, exist_ok=True)
    cwd.mkdir(parents=True, exist_ok=True)
    for rel, content in (files or {}).items():
        base = cwd if rel.startswith("./") else home
        path = base / rel.removeprefix("./").removeprefix("~/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content, indent=2), encoding="utf-8")
    return ReconPaths(home=home, cwd=cwd, env=dict(setup.get("env") or {}))


def run_scenario(scenario: Path, out_root: Path) -> ScenarioResult:
    truth = json.loads((scenario / "truth.json").read_text(encoding="utf-8"))
    snap = load_fixture(scenario / "fixture.json")
    out_dir = out_root / scenario.name
    with tempfile.TemporaryDirectory(prefix="agent-radius-bench-") as tmp:
        recon_paths = _materialise(truth.get("setup") or {}, Path(tmp))
        board = run_scan(
            snap,
            RunOptions(out_dir=out_dir, backend=NoneBackend(), recon_paths=recon_paths, terraform_bin="auto", parallel=True),
        )
    reported = board.verified
    failures: list[str] = []
    met = 0
    for m in truth.get("expect", []):
        if any(_matches(m, f) for f in reported):
            met += 1
        else:
            failures.append("missing expected: " + json.dumps(m, sort_keys=True))
    violated = 0
    outputs = None
    for m in truth.get("must_not", []):
        if "output_contains" in m:
            if outputs is None:
                outputs = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in out_dir.rglob("*") if p.is_file())
            if m["output_contains"] in outputs:
                violated += 1
                failures.append("output contains forbidden text (redaction failure)")
            continue
        hits = [f for f in reported if _matches(m, f)]
        if hits:
            violated += 1
            failures.append(f"must_not matched {len(hits)} finding(s): " + json.dumps(m, sort_keys=True) + f" e.g. {hits[0].title}")
    halluc = _hallucinations(snap, reported)
    failures += [f"hallucination: {h}" for h in halluc]
    expected_total = len(truth.get("expect", []))
    return ScenarioResult(
        name=scenario.name,
        passed=(met == expected_total and violated == 0 and not halluc),
        expected_total=expected_total,
        expected_met=met,
        must_not_total=len(truth.get("must_not", [])),
        must_not_violated=violated,
        hallucinations=len(halluc),
        verifier_dropped=len(board.dropped),
        findings_reported=len(reported),
        failures=failures,
    )


def run_bench(scenarios: Path | None = None, out_root: Path | None = None, results_path: Path | None = None) -> dict[str, Any]:
    base = scenarios or scenarios_dir()
    dirs = sorted(p for p in base.iterdir() if (p / "fixture.json").is_file() and (p / "truth.json").is_file())
    own_tmp = None
    if out_root is None:
        own_tmp = tempfile.TemporaryDirectory(prefix="agent-radius-bench-out-")
        out_root = Path(own_tmp.name)
    try:
        results = [run_scenario(d, out_root) for d in dirs]
    finally:
        if own_tmp is not None:
            own_tmp.cleanup()
    tp = sum(r.expected_met for r in results)
    fn = sum(r.expected_total - r.expected_met for r in results)
    fp = sum(r.must_not_violated for r in results)
    summary = {
        "scenarios": len(results),
        "passed": sum(r.passed for r in results),
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else 1.0,
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else 1.0,
        "hallucinations": sum(r.hallucinations for r in results),
        "verifier_dropped": sum(r.verifier_dropped for r in results),
        "llm_backend": "none",
    }
    payload = {"summary": summary, "scenarios": [asdict(r) for r in results]}
    if results_path is not None:
        results_path.parent.mkdir(parents=True, exist_ok=True)
        results_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload
