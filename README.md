# AgentForge

A multi-agent adversarial evaluation platform that continuously discovers,
evaluates, escalates, and documents vulnerabilities in an AI-assisted clinical
workflow — the **Clinical Co-Pilot** (deployed at
[clinical-copilot-agent.onrender.com](https://clinical-copilot-agent.onrender.com),
embedded in [OpenEMR](https://openemr-oy5a.onrender.com)).

Five agent roles (Orchestrator, Red Team, Judge, Documentation, and a
deterministic Regression Harness) attack a live target through one seam,
score results against fixed rubrics, and turn confirmed exploits into
reproducible reports — never a static payload list. Full rationale:
[ARCHITECTURE.md](ARCHITECTURE.md).

## Status

Build sequence and phase-by-phase progress: [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md).

| Phase | Deliverable | Status |
|---|---|---|
| 0 — Architecture Defense | [ARCHITECTURE.md](ARCHITECTURE.md), [docs/BUILD_VS_CONFIGURE.md](docs/BUILD_VS_CONFIGURE.md), [docs/EVIDENCE_PACKET.md](docs/EVIDENCE_PACKET.md), [contracts/](contracts/) | ✅ |
| 1 — Stand Up the Target | [TARGET.md](TARGET.md), [agentforge/target_adapter.py](agentforge/target_adapter.py) | ✅ |
| 2 — Map the Attack Surface | [THREAT_MODEL.md](THREAT_MODEL.md) | ✅ |
| 3 — Attack Suite (`./evals/`) | [evals/](evals/), [contracts/eval_case.schema.json](contracts/eval_case.schema.json), [agentforge/eval_runner.py](agentforge/eval_runner.py) | ✅ |
| 4 — First Agent Live (Judge) | | not started |
| 5 — Red Team Agent | | not started |
| 6 — Orchestrator + Regression | | not started |
| 7 — Documentation Agent | | not started |
| 8 — Observability, Cost, Hardening | | not started |

## Repo layout

```
ARCHITECTURE.md        five-agent design, trust levels, inter-agent diagram
IMPLEMENTATION_PLAN.md  phase-by-phase build plan mapped to the schedule
TARGET.md               the deployed target, what changed to reach it, the adapter
THREAT_MODEL.md         six attack categories mapped to real code, OWASP-tagged, ranked
contracts/              versioned JSON Schemas — the seam between every agent pair
agentforge/             the platform's own code (target adapter, eval loader + runner)
evals/                  the attack suite: YAML seed cases + the live runner CLI
tests/                  pytest suite (live tests hit the real deployed target — no mocks)
docs/                   build-vs-configure decision record, evidence packet skeleton
target/                 local read-only clones of the target repos (gitignored, reference only)
```

## The attack suite (`./evals/`)

Reproducible eval cases run live against the deployed target. Each case
(`evals/cases/**/*.yaml`) pins a **boundary, an invariant, or a regression
risk** — never a flat payload — validated against
[contracts/eval_case.schema.json](contracts/eval_case.schema.json), executed
through the one target seam, and graded by a deterministic detector.

```bash
python -m evals.run --list      # load + validate every case (no network)
python -m evals.run --dry-run   # show the execution plan (no network)
python -m evals.run             # run all cases live, write a JSONL run log
python -m evals.run --case <case_id>      # run one case
python -m evals.run --category state_corruption
```

Seed cases span four categories (`data_exfiltration`, `identity_role`,
`state_corruption`, `prompt_injection`). The first live run confirmed two
critical/high findings — the unauthenticated-PHI auth bypass (§1) and a
**cross-patient conversation-memory bleed** (§5), the latter a previously
untested hypothesis the suite confirmed on its first attempt. Cases marked
`requires_judge` carry a coarse deterministic signal that the Phase 4 Judge
will finalize; their verdicts are provisional (`authority: judge_pending`) and
never raise a false "surprise".

### Dashboard

```bash
python -m evals.dashboard          # -> evals/results/dashboard.html
python -m evals.dashboard --open   # build and open in the browser
```

Renders a self-contained HTML console from the run logs (summary tiles,
per-category pass/fail, an expandable results table with the full target
transcript per step, and a run-over-run history). It embeds real demo-patient
identifiers and confirmed findings, so it is written to the gitignored
`evals/results/` directory and kept local — an operator console, not something
to publish. This is an early slice of the Phase 8 observability surface.

## Running the tests

```bash
pip install -e .
python -m pytest tests/ -v
```

`pytest -m live` (included by default) makes real calls against the deployed
target — per the platform's guiding constraint, nothing here is a mock.
