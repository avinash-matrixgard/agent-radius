from __future__ import annotations

import json

from agent_radius.agents.orchestrator import RunOptions, run_scan
from tests.helpers import ADMIN, make, rds_arn, role, role_arn


def test_report_is_traceable_and_html_is_escaped(tmp_path):
    snap = make(
        roles=[role("agent", attached=[ADMIN])],
        resources={"rds_instances": [{"identifier": "prod-db", "arn": rds_arn("prod-db"), "tags": {"env": "prod"}}]},
        local_credentials=[{"id": "cred:x", "source_type": "mcp_config", "path": "<script>alert(1)</script>",
                            "principal_arn": role_arn("agent"), "has_static_keys": True, "key_names": ["AWS_ACCESS_KEY_ID"]}],
    )
    board = run_scan(snap, RunOptions(out_dir=tmp_path, terraform_bin=None))
    report = json.loads((tmp_path / "report.json").read_text())
    ids = {f["id"] for f in report["findings"]}
    for item in report["headline_items"]:
        assert item["finding_id"] in ids and item["evidence_ids"]
    irr = [i["irreversibility"] for i in report["headline_items"]]
    assert irr == sorted(irr, reverse=True)
    assert report["trace"] and {t["agent"] for t in report["trace"]} >= {"planner", "recon", "permissions", "backup", "guardrail", "verifier"}
    html = (tmp_path / "report.html").read_text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert board.report["verification"]["dropped"] == 0
