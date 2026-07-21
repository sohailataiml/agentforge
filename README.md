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
| 3 — Attack Suite (`./evals/`) | | not started |
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
agentforge/             the platform's own code (currently: target_adapter.py)
tests/                  pytest suite (live tests hit the real deployed target — no mocks)
docs/                   build-vs-configure decision record, evidence packet skeleton
target/                 local read-only clones of the target repos (gitignored, reference only)
```

## Running the tests

```bash
pip install -e .
python -m pytest tests/ -v
```

`pytest -m live` (included by default) makes real calls against the deployed
target — per the platform's guiding constraint, nothing here is a mock.
