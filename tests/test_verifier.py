"""The Verifier drops forged and hallucinated findings and runs the what-if."""

from __future__ import annotations

from agent_radius.agents.backup import Backup
from agent_radius.agents.blackboard import Blackboard
from agent_radius.agents.findings import Evidence, Finding
from agent_radius.agents.guardrail import Guardrail
from agent_radius.agents.orchestrator import RunOptions, run_scan
from agent_radius.agents.permissions import Permissions
from agent_radius.agents.planner import Planner
from agent_radius.agents.recon import Recon
from agent_radius.agents.verifier import Verifier
from agent_radius.iam.evaluator import Evaluator
from agent_radius.llm.advisor import Advisor
from agent_radius.llm.none_backend import NoneBackend
from tests.helpers import ADMIN, allow, doc, make, rds_arn, role, role_arn

DB = rds_arn("prod-db")


def _snap():
    return make(
        roles=[role("agent", inline={"Rds": doc(allow(["rds:DeleteDBInstance", "rds:Describe*"]))}), role("bystander")],
        resources={"rds_instances": [{"identifier": "prod-db", "arn": DB, "tags": {"env": "prod"}}],
                   "dynamodb_tables": [{"name": "orders-prod", "arn": "arn:aws:dynamodb:us-east-1:111122223333:table/orders-prod"}]},
        agent_principals=[role_arn("agent")],
    )


def _board_until_guardrail(snap, tmp_path=None):
    board = Blackboard(snapshot=snap, evaluator=Evaluator(snap), out_dir=tmp_path)
    advisor = Advisor(NoneBackend())
    for agent in (Planner(advisor), Recon(), Permissions(), Backup(), Guardrail()):
        agent.execute(board)
    return board


def _forge(board, **kw):
    base = dict(kind="destructive_permission", agent="permissions", title="forged", severity="critical",
                principal=role_arn("agent"), outcome="ALLOW", irreversibility=3,
                evidence=[Evidence("statement", "inline:role/agent/Rds#0"), Evidence("fixture", board.snapshot.source)])
    base.update(kw)
    f = Finding(**base)
    board.post("permissions", f)
    return f


def test_forged_and_hallucinated_findings_are_dropped():
    board = _board_until_guardrail(_snap())
    genuine = [f.id for f in board.findings.values() if f.kind == "destructive_permission"]
    forged_outcome = _forge(board, action="dynamodb:DeleteTable", resource="arn:aws:dynamodb:us-east-1:111122223333:table/orders-prod")
    fake_arn = _forge(board, action="rds:DeleteDBInstance", resource=rds_arn("billing-db-that-does-not-exist"))
    fake_action = _forge(board, action="rds:NukeEverything", resource=DB)
    fake_stmt = _forge(board, action="rds:DeleteDBInstance", resource=DB,
                       evidence=[Evidence("statement", "inline:role/agent/Invented#7")], data={"id_salt": "x"})
    fake_principal = _forge(board, principal=role_arn("ghost"), action="rds:DeleteDBInstance", resource=DB)
    wrong_verdict = Finding(kind="backup_survivability", agent="backup", title="forged verdict", severity="info",
                            principal=role_arn("agent"), resource=DB, verdict="SURVIVES",
                            evidence=[Evidence("resource", DB)], data={"id_salt": "forged"})
    board.post("backup", wrong_verdict)
    leaky = _forge(board, action="rds:DeleteDBInstance", resource=DB, title="key AKIATESTFIXTUREXYZ12 leaked",
                   data={"id_salt": "leak"})

    Verifier(terraform_bin=None).execute(board)
    dropped = {d["finding_id"]: d["reason"] for d in board.dropped}
    assert "does not reproduce" in dropped[forged_outcome.id]
    assert "not in the snapshot" in dropped[fake_arn.id]
    assert "catalog" in dropped[fake_action.id]
    assert "does not exist" in dropped[fake_stmt.id]
    assert "ghost" in dropped[fake_principal.id]
    assert "AT_RISK" in dropped[wrong_verdict.id]
    assert "secret" in dropped[leaky.id]
    verified_ids = {f.id for f in board.verified}
    assert set(genuine) <= verified_ids
    assert not verified_ids & set(dropped)
    assert any(t.event == "drop" for t in board.trace)


def test_what_if_marks_every_destructive_permission_blocked(tmp_path):
    snap = make(roles=[role("agent", attached=[ADMIN])], resources={"rds_instances": [{"identifier": "prod-db", "arn": DB}]},
                agent_principals=[role_arn("agent")])
    board = run_scan(snap, RunOptions(out_dir=tmp_path, terraform_bin=None))
    perms = [f for f in board.verified if f.kind == "destructive_permission"]
    assert perms and all(f.data["guardrail_what_if"]["blocked"] for f in perms)
    wi = board.verification["what_if"]
    assert wi["checked"] == len(perms) == wi["blocked"]
    backup = next(f for f in board.verified if f.kind == "backup_survivability")
    assert backup.verdict == "AT_RISK" and backup.data["guardrail_what_if"]["verdict_after"] == "SURVIVES"
    assert board.verification["terraform_validate"] == {"status": "skipped", "reason": "terraform not installed"}
    assert board.verification["hcl_check"]["status"] == "passed"


def test_terraform_validate_runs_when_a_binary_is_present(tmp_path):
    calls = []

    class Proc:
        def __init__(self, stdout="", returncode=0):
            self.stdout, self.returncode, self.stderr = stdout, returncode, ""

    def runner(cmd, **kw):
        calls.append(cmd)
        if "validate" in cmd:
            return Proc('{"valid": true, "error_count": 0, "warning_count": 0, "diagnostics": []}')
        return Proc()

    snap = make(roles=[role("agent", attached=[ADMIN])], agent_principals=[role_arn("agent")])
    board = _board_until_guardrail(snap, tmp_path)
    Verifier(terraform_bin="/fake/terraform", runner=runner).execute(board)
    assert board.verification["terraform_validate"]["status"] == "passed"
    assert calls[0][:2] == ["/fake/terraform", f"-chdir={tmp_path / 'guardrails'}"] and "init" in calls[0]
    assert "-backend=false" in calls[0]
