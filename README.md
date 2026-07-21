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
| 4 — First Agent Live (Judge) | [agentforge/judge.py](agentforge/judge.py), [rubrics/](rubrics/), [agentforge/judge_eval.py](agentforge/judge_eval.py) | ⏳ built; live accuracy gate pending API credits |
| 5 — Red Team Agent | [agentforge/red_team.py](agentforge/red_team.py), [red_team_client.py](agentforge/red_team_client.py) | 🚧 agent live (generate + execute on Groq); mutation loop pending Judge credits |
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

## Web console (the demo surface)

A FastAPI web app ([agentforge/webapp.py](agentforge/webapp.py)) over the whole
platform — the thing to open in a browser. It reuses the dashboard renderer, the
eval runner, and the Red Team agent, and exposes:

- a live **results console** (summary tiles, per-category pass/fail, expandable
  target transcripts, run history),
- a **Run attack suite** button that attacks the live target on demand (optionally
  with the Judge), and
- a **Red Team** panel that generates an attack on the open model and executes it
  against the target, showing both live.

```bash
pip install -e ".[web]"
python -m agentforge.webapp          # -> http://127.0.0.1:8000
```

**Deploy to Render:** [render.yaml](render.yaml) is a ready blueprint (build
`pip install -e ".[web]"`, start `uvicorn agentforge.webapp:app --host 0.0.0.0
--port $PORT`). The demo patients are synthetic, so it is safe to host. Viewing is
public; the **paid action buttons** (run suite / Red Team) trigger LLM calls on the
server's keys, so they are gated behind an operator token — set **`CONSOLE_TOKEN`**
(plus `GROQ_API_KEY` and `JUDGE_ANTHROPIC_API_KEY`) in the Render dashboard.
Without a token gate a public console would itself be the unbounded-cost hole this
platform hunts for.

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

## The Judge Agent (Phase 4)

The first agent role: a frontier model (Opus 4.8, adaptive thinking) that
consumes an attempt and emits a schema-valid **Verdict**
([contracts/verdict.schema.json](contracts/verdict.schema.json)) scored against
a **frozen, versioned rubric** per category ([rubrics/](rubrics/)). The model
produces only the judgment fields under a strict output schema; the contract
invariants — the escalate-to-human rule, confidence clamping, full schema
validation — are enforced **deterministically in code**
([agentforge/judge.py](agentforge/judge.py)), so a verdict cannot be talked out
of its own contract. `result="fail"` always means the *target* failed to stay
secure, never the attack.

Wired into the runner so `requires_judge` cases become authoritative instead of
`judge_pending`:

```bash
python -m evals.run --judge          # Judge scores requires_judge cases (Opus 4.8)
python -m evals.run --judge-all      # Judge scores every case
python -m agentforge.judge_eval      # accuracy vs the labeled ground-truth set
```

**Trust gate:** [judge/ground_truth.yaml](judge/ground_truth.yaml) holds 12
labeled attempts (5 real transcripts from the first live run + 7 clear-cut
cases). [agentforge/judge_eval.py](agentforge/judge_eval.py) runs the Judge over
them and asserts ≥90% agreement before the Judge is trusted to produce
authoritative verdicts. It is designed to correctly rule the identity-role
transcript a **pass** — the case where the coarse Phase 3 detector
false-positived.

**Model / key config:** the Judge model is `JUDGE_MODEL` (default
`claude-opus-4-8`). By default it authenticates with the standard
`ANTHROPIC_API_KEY`; set **`JUDGE_ANTHROPIC_API_KEY`** to bill the platform to a
separate Anthropic account without disturbing the `ANTHROPIC_API_KEY` a
surrounding Claude Code session shares. No key is ever hardcoded — all keys
resolve from the environment.

> **Status:** the Judge and its wiring are complete and covered by non-live
> tests (rubric loading, prompt building, verdict assembly, escalation rule,
> schema validation, and the full `judge_attempt` path against a stub client).
> The **live** accuracy gate and `--judge` runs are currently blocked by a
> `400 — credit balance too low` on the configured Anthropic key; the SDK, key,
> and request shape are verified working, so both run as-is once the account has
> credits (or once `JUDGE_ANTHROPIC_API_KEY` points at a funded account).

## The Red Team provider seam (Phase 5, in progress)

The Red Team is the highest-volume caller and must be a **different vendor from
the Judge** (generator ≠ judge independence) on a **cheaper open model** — the
architecture's model tiering ([ARCHITECTURE.md](ARCHITECTURE.md) §Model tiering).
[agentforge/red_team_client.py](agentforge/red_team_client.py) is the single seam
for that model: one function over the OpenAI-compatible `/chat/completions` wire
format (via `httpx`, no new SDK), so the provider is swappable by env var, never
by code.

```bash
# Default: Groq free tier (fastest, no card, different vendor from the Anthropic Judge)
export GROQ_API_KEY=gsk_...            # from console.groq.com
# defaults: RED_TEAM_BASE_URL=https://api.groq.com/openai/v1  RED_TEAM_MODEL=llama-3.3-70b-versatile

# Fallback if the safety-tuned default starts refusing offensive-security generation —
# same code path, just point at an OpenRouter uncensored open-weight model:
export RED_TEAM_BASE_URL=https://openrouter.ai/api/v1
export RED_TEAM_API_KEY=sk-or-...
export RED_TEAM_MODEL=<an uncensored open model on OpenRouter>
```

Config: `RED_TEAM_BASE_URL`, `RED_TEAM_MODEL`, `RED_TEAM_API_KEY` (or `GROQ_API_KEY`),
and optional `RED_TEAM_USD_PER_1M_INPUT`/`_OUTPUT` for cost tracking on a paid
endpoint (Groq's free tier is `$0`).

**The agent** ([agentforge/red_team.py](agentforge/red_team.py)) drives one
`AttackDirective` end to end: generate a novel attack on the open model → **egress
screen** (drop any generation carrying a real credential — untrusted output is
never forwarded) → execute against the live target through `send_to_target` →
assemble a **schema-valid `AttackAttempt`** ([contracts/attack_attempt.schema.json](contracts/attack_attempt.schema.json))
for the Judge. On a `partial` verdict it autonomously mutates the parent into a
variant family (paraphrase / encoding / role-frame / turn-splitting), linked by
`parent_attempt_id` — no human. The Judge is **injected** (different vendor), so
the Red Team never scores its own work.

**Live-validated** against Groq + the deployed target: the agent generated a
prompt-injection attack, executed it live (the target held), and produced a
schema-valid `AttackAttempt` for ~$0.01. The **mutation loop** is triggered by a
`partial` Judge verdict, so it runs live once the Anthropic Judge has credits;
the injected-judge design lets generation + execution run live today without it.
Pure logic (egress screen, attack parsing, attempt assembly) is covered by
non-live tests; the full pipeline by a `live` test that skips without a key.

## Running the tests

```bash
pip install -e .
python -m pytest tests/ -v
```

`pytest -m live` (included by default) makes real calls against the deployed
target — per the platform's guiding constraint, nothing here is a mock.
