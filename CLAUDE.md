# CLAUDE.md: Agent Radius

Contributor notes for humans and coding agents. Keep this file under 200 lines; put detail in `docs/`.

## What this is

A read-only, offline-first, multi-agent auditor: what could an AI coding agent destroy with the AWS credentials it inherits, would backups survive, and what guardrail fixes it. AWS only in v1. AGPL-3.0-or-later. Author: MatrixGard.

## Hard rules

1. **Never call a real cloud API from tests or development.** Tests use `tmp_path` and moto only. `tests/conftest.py` points HOME and the AWS config files at temp paths; keep it that way.
2. **Every AWS call goes through `security/readonly_gate.py`.** Adding a live operation means adding its exact name to `READ_ONLY_OPERATIONS` and to `LIVE_OPERATIONS` in `snapshot/collector.py`. Never add a mutating or secret-reading operation. The tests will fail if you do.
3. **Never read, store, log or emit a secret value.** Recon keeps key names and paths; access key IDs only as fingerprints. Never send credential files to an LLM.
4. **No paid LLM calls in tests or the bench.** The bench always uses the `none` backend. Test `anthropic` and `claude-cli` with fakes.
5. **The LLM never creates findings.** It may reorder the plan, rank and explain verified findings. Keep all model calls inside `llm/advisor.py`.
6. **No em dash character anywhere** (code, docs, strings, output). `tests/test_repo_hygiene.py` enforces it.
7. **Never fabricate numbers.** Any figure in README or docs comes from a command you actually ran, pasted verbatim.

## Authenticity rule for the bench

Benchmarks are regression guards, not goals. If a scenario fails, fix the engine. Change an expectation only when the expectation is wrong, and say why in the commit. Never special-case a scenario name, ARN or fixture value in engine code.

## Layout

- `snapshot/` model, fixture loader, live collector
- `security/` read-only gate, redaction
- `iam/` matching, policy parsing, evaluator (semantics: `docs/IAM_SEMANTICS.md`)
- `catalog/` destructive actions (irreversibility 1 to 3, consequence, category)
- `agents/` blackboard, tools, planner, recon, permissions, backup, guardrail, verifier, reporter, orchestrator; `assess.py` holds the pure logic the Verifier re-runs
- `guardrails/` HCL render, parse and structural check; Terraform bundle
- `llm/` backends, schema validator, sanitiser, advisor
- `bench/` runner and `scenarios/<name>/{fixture.json,truth.json}`

Design: `docs/DESIGN.md`. Security model: `SECURITY.md`.

## Commands

```bash
uv venv --python 3.11 .venv && uv pip install -e ".[dev]"
.venv/bin/python -m pytest
.venv/bin/ruff check src tests
.venv/bin/agent-radius bench        # writes bench/results.json
.venv/bin/agent-radius demo
```

## How to

- **Add a catalog action:** append to `CATALOG` in `catalog/actions.py` with a real IAM action name (check the AWS Service Authorization Reference; for example EFS is `elasticfilesystem:`, not `efs:`). If the resource type is modelled, map it in `Snapshot.resource_index()`.
- **Add a resource protection:** extend `effective_permission()` in `agents/assess.py`, then add a bench scenario that would fail without it.
- **Add a stateful resource type:** model it in `snapshot/model.py`, collect it in `collector.py` through the gate, add an `_assess_*` function, and add it to `STATEFUL_TYPES`.
- **Add a scenario:** a directory under `src/agent_radius/bench/scenarios/` with `fixture.json` and `truth.json` (matcher keys are listed in `bench/runner.py`). Include at least one must-not rule.
