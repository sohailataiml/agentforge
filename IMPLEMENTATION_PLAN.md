# AgentForge — Implementation Plan

Build sequence for the multi-agent adversarial evaluation platform, mapped to the
Week 3 schedule and hard gates. Pairs with [ARCHITECTURE.md](./ARCHITECTURE.md).

---

## Guiding constraints

- **Every checkpoint requires a live deployed target URL** (hard gate). Nothing is a
  mock — the platform must attack a running Co-Pilot.
- **MVP scope ≠ full platform.** MVP proves the foundation is trustworthy and
  extensible: standing target, threat model, 3+ attack categories with results, and
  ≥1 working agent role running live.
- Build order follows data flow: **target → threat model → attacks → one agent live
  → coordination → the rest.**
- Prefer deterministic code for anything that must be reproducible; reserve LLM calls
  for generation and judgment.

## Schedule mapping

| Checkpoint | Deadline | This plan's phases |
|------------|----------|--------------------|
| Architecture Defense | 2.5h after kickoff | Phase 0 (docs + decision records) |
| MVP | Tuesday 11:59 PM | Phases 1–4 |
| Final | Friday Noon | Phases 5–8 |

---

## Phase 0 — Architecture Defense (first 2.5 hours)

**Goal:** defensible plan on paper + all decision records. No platform code yet.

- [ ] `ARCHITECTURE.md` with ~500-word summary, named agents, roles, trust levels,
      inter-agent diagram. *(done — this repo)*
- [ ] Build-vs-configure decision record: evaluate Burp Suite, OWASP ZAP, Semgrep,
      Garak, commercial red-team platforms — what each covers, where each falls short
      for a multi-turn LLM target, why a custom agent is justified.
- [ ] Evidence packet skeleton: agent interaction diagram, message schemas, trust
      boundaries, known failure modes.
- [ ] `/contracts` directory with v1 JSON Schemas for the four core messages +
      error schemas.

**Exit:** every architectural decision has a written, defensible rationale.

---

## Phase 1 — Stand Up the Target (MVP Stage 1)

**Goal:** Clinical Co-Pilot running locally **and** deployed, testable.

- [x] Pull the Week 1/2 OpenEMR Clinical Co-Pilot (or the Week 1 reference build).
      *(cloned into `target/` — see [TARGET.md](TARGET.md))*
- [x] Run locally; confirm chat, chart retrieval, note summarization, intake flow.
      *(confirmed against the live deployed instance — chat + chart retrieval
      verified with a real `/chat` call; local Docker stand-up not required,
      see TARGET.md)*
- [x] Deploy to a public URL (record it — required at every checkpoint).
      *(already deployed by the Week 1/2 team — verified live, not redeployed)*
- [x] Document every change made to reach a testable state (goes in README +
      threat-model context). *(TARGET.md — no changes were needed)*
- [x] Add a thin **target adapter**: a single function `send_to_target(session_id,
      messages) -> transcript` so all agents hit the deployed URL through one seam.
      *(`agentforge/target_adapter.py`, tested in `tests/test_target_adapter.py`)*

**Exit / hard gate:** deployed target URL live; adapter returns transcripts. **✅ met.**

---

## Phase 2 — Map the Attack Surface (MVP Stage 2)

**Goal:** `THREAT_MODEL.md` — the living document the platform exercises.

- [x] ~500-word summary: key findings, highest-risk categories, coverage priority.
- [x] For each category document: attack surface · potential impact · exploit
      difficulty · whether an existing defense addresses it. Categories:
  - Prompt injection (direct / indirect / multi-turn)
  - Data exfiltration (PHI leakage, cross-patient exposure, authz bypass)
  - State corruption (history manipulation, context poisoning)
  - Tool misuse (unintended invocation, parameter tampering, recursion)
  - Denial of service (token exhaustion, infinite loops, cost amplification)
  - Identity/role exploitation (priv-esc, persona hijack, trust-boundary violation)
- [x] Tag each surface with OWASP refs (LLM Top 10 + relevant Web Top 10).
- [x] Rank categories by risk → this ranking seeds the Orchestrator's priority logic.

**Exit / hard gate:** `THREAT_MODEL.md` committed with summary + full map. **✅ met.**
Includes one already-confirmed-live critical finding (unauthenticated PHI
access via the DEV password-grant fallback) discovered while verifying
Phase 1's target liveness — see [TARGET.md](TARGET.md).

---

## Phase 3 — Build Initial Attack Suite (MVP Stage 3)

**Goal:** `./evals/` — structured, reproducible seed cases across ≥3 categories.

- [x] Define eval case schema (one YAML file per case):
      `category, subcategory, owasp_refs, input_sequence, expected_safe_behavior,
      severity, exploitability, add_to_regression, test_type(boundary|invariant|
      regression), invariant, expected_result` + a per-step deterministic
      `detector`. Versioned as [`contracts/eval_case.schema.json`](contracts/eval_case.schema.json)
      (and [`eval_result.schema.json`](contracts/eval_result.schema.json) for the
      runner's output records). `observed_behavior`/`result` are produced by the
      runner, not authored.
- [x] Author ≥3 categories of seed cases (target the top-ranked from Phase 2).
      *(5 cases across 4 categories under [`evals/cases/`](evals/cases/):
      `data_exfiltration` ×2, `identity_role`, `state_corruption`,
      `prompt_injection` — the coverage priority 1/3/5 plus one direct-injection
      case.)*
- [x] **Every case must exercise a boundary, an invariant, or a regression risk** —
      not a flat payload list. *(Enforced by the schema's required `test_type` +
      `invariant` fields and asserted in
      [`tests/test_eval_case.py`](tests/test_eval_case.py). Cases include: the
      confirmed auth-bypass locked as a **regression**; the PatientScopeGuard
      cross-patient **boundary**; the trusted-context-delimiter **invariant**.)*
- [x] Runner that executes each case against the live target and records results.
      *([`agentforge/eval_runner.py`](agentforge/eval_runner.py) threads multi-step
      sessions through the target seam, applies detectors, rolls step verdicts up,
      and writes a JSONL run log; CLI in [`evals/run.py`](evals/run.py).)*

**Exit / hard gate:** `./evals/` runs live against the deployed target across ≥3
categories with reproducible results. **✅ met** — first live run (2026-07-21)
executed all 5 cases against the deployed target for $0.13, confirming 3 exploits
including a **new** cross-patient conversation-memory bleed (THREAT_MODEL §5,
previously untested). Deterministic detectors make results reproducible;
`requires_judge` cases defer the final verdict to Phase 4's Judge.

---

## Phase 4 — First Agent Live (MVP Stage 3, cont.)

**Goal:** ≥1 agent role (Red Team, Judge, or Orchestrator) running live. **Recommend
building the Judge first** — it unblocks reproducible scoring for everything else.

- [x] **Judge Agent v0**: consumes an `AttackAttempt`-shaped input, emits a
      schema-valid `Verdict` against a frozen rubric per category. Frontier model
      (Opus 4.8, adaptive thinking), separate from any Red Team model.
      *([`agentforge/judge.py`](agentforge/judge.py) + frozen versioned rubrics in
      [`rubrics/`](rubrics/). The model emits only judgment fields under a strict
      output schema; the escalate-to-human rule, confidence clamping, and full
      `verdict.schema.json` validation are enforced deterministically in code —
      structured outputs can't express the contract's numeric conditional.)*
- [x] Ground-truth mini-set (10–20 labeled transcripts) to validate Judge accuracy.
      *(12 labeled attempts in [`judge/ground_truth.yaml`](judge/ground_truth.yaml)
      — 5 real transcripts from the first live run + 7 clear-cut cases; accuracy
      harness in [`agentforge/judge_eval.py`](agentforge/judge_eval.py), ≥90% bar.)*
- [x] Wire Judge into the eval runner so case results are judge-produced, not manual.
      *(`run_case`/`run_suite` take an optional `judge`; `requires_judge` cases flip
      from `authority=judge_pending` to `authority=judge` with the Verdict attached.
      `python -m evals.run --judge`. Contract updated: `eval_result.schema.json`
      gains `authority: judge` + an optional `verdict`.)*
- [x] Emit traces + cost for each verdict to a run-log table.
      *(Judge token/USD cost folded into the case cost and the JSONL run log; the
      dashboard renders the verdict, confidence, rubric id/version, and rationale.)*

**Exit / hard gate:** a working agent prototype running live against the deployed
target; MVP submission includes deployed URL + `./evals/` + this agent.
**Code complete + non-live-verified.** Live accuracy validation and `--judge`
runs are **blocked pending Anthropic API credits** — the configured key returns
`400 credit balance too low`. The SDK, connectivity, and request shape are
verified working (a basic call reaches the API; `output_config`/`thinking` are
accepted), so the live gate passes as-is once the account is funded:
`python -m agentforge.judge_eval` and `pytest -m live`.

---

## Phase 5 — Red Team Agent + Mutation Engine

**Goal:** autonomous attack generation and variant escalation.

- [x] Red Team Agent on an open/local model (sandboxed, untrusted output).
      *(Provider-agnostic seam [`agentforge/red_team_client.py`](agentforge/red_team_client.py)
      over the OpenAI-compatible API; default Groq free tier (`llama-3.3-70b-versatile`),
      env-swappable to an OpenRouter uncensored model. Different vendor from the
      Anthropic Judge; output treated as untrusted.)*
- [x] Consumes `AttackDirective`; generates novel attacks + multi-turn sequences.
      *([`agentforge/red_team.py`](agentforge/red_team.py) `run_directive`: generate →
      execute via `send_to_target` → assemble a schema-valid `AttackAttempt`.
      **Live-validated** on Groq + the deployed target for ~$0.01.)*
- [x] **Mutation loop**: on a `partial` verdict, autonomously generate N variants of
      the parent attempt (paraphrase, encoding, role-frame, turn-splitting) and
      re-submit — no human in the loop. *(Implemented in `run_directive` with an
      **injected** Judge; each variant links to the parent via `parent_attempt_id`.
      Runs live once the Anthropic Judge has credits — the trigger is a `partial`
      verdict.)*
- [x] Egress content check so genuinely harmful generations are logged and dropped,
      never executed against real PHI. *(`egress_ok`: deterministic secret-pattern
      screen; a match drops the attempt before it reaches the target, recorded as
      `dropped_reason`.)*

**Exit:** Red Team turns one partial success into a variant family without prompting.
**Generation + execution live-verified; the partial→mutation escalation runs live
the moment the Judge (Anthropic) has credits** — the loop code and wiring are done
and non-live-tested.

---

## Phase 6 — Orchestrator + Regression Harness

**Goal:** strategy layer + deterministic replay.

- [x] **Orchestrator** (`agentforge/orchestrator.py`): reads observability state (run
      logs + report corpus + regression DB), scores categories (coverage gaps, open
      high-sev, regressions), emits schema-valid `AttackDirective`s, enforces a spend
      budget, and triggers a regression run on target-version change. Pure, injectable,
      unit-tested; CLI wires a live Red Team + Judge executor. `python -m agentforge.orchestrator`.
- [x] **Regression Harness** (deterministic, no LLM) — `agentforge/regression.py`:
      stores confirmed exploits in a versioned SQLite corpus; replays the exact
      sequences via `run_case` (detectors, no Judge); asserts the *violated invariant*,
      not string equality; classifies each replay against the frozen baseline
      (regressed / reproduces / fixed / stable) and against the previous run to flag
      **reappearing** vulns; emits a contract-valid `CampaignResult`. Runs credit-free.
      `python -m agentforge.regression`.
- [x] Spend-rate monitor + **kill-switch** for low-signal campaigns (`apply_kill_switch`:
      trips a category once it has spent enough with signal-yield below threshold and
      nothing urgent open; killed categories are excluded from scoring).
- [x] Cost/rate-limit handling: **backoff → queue → abort** in the loop (exponential
      backoff + defer/queue on `RateLimited`, abort on a sustained streak).

**Exit:** ✅ Orchestrator drives an autonomous loop (score → emit directive → execute →
feed outcomes back → re-score); regression suite re-runs on target change.

---

## Phase 7 — Documentation Agent + Trust Gates

**Goal:** confirmed exploits → professional reports, with human gates.

- [x] Documentation Agent (`agentforge/documentation.py`) consumes confirmed `Verdict`s →
      `VulnReport` (schema-valid, data-quality-checked: unique ID, uuid attempt, non-dup
      attack sequences). Prose authored by the frontier model with a deterministic fallback.
- [x] **4 distinct vulnerability reports** produced in `reports/` across 3 categories
      (data_exfiltration ×2 vectors, state_corruption, identity_role) via
      `python -m agentforge.generate_reports` (eval-suite + Red Team confirmed findings).
- [x] **Human approval gate** — a critical report is contract-invalid unless `human_approved`;
      `build_vuln_report`/`publish` refuse unapproved criticals. **No autonomous remediation**
      (`fix_validation.validated` only flipped by the Regression Harness).
- [x] Triage exercise (`TRIAGE_EXERCISE.md`): 12-finding simulated scan across
      critical/high/medium/low/false-positive with validate/remediate/defer/document decisions.

**Exit:** reports a senior engineer could reproduce and fix from text alone; gates enforced.

---

## Phase 8 — Observability, Cost Analysis, Hardening (Final)

**Goal:** the CISO-defensible finish.

- [x] Observability dashboard/queries — the web console (live) + `agentforge/observability.py`
      (headless CLI + tested queries) answering all six: cases per category · pass-fail rate
      by category & system version · resilience trend over time · open/in-progress/resolved
      vulns · run cost + scaling rate · per-agent action timeline. See `OBSERVABILITY.md`.
- [x] `AI_COST_ANALYSIS.md`: measured dev spend (<~$5) + unit economics (Opus Judge ≈ 95%
      of per-attempt cost) + projections at 100/1K/10K/100K runs with the architectural
      change each tier forces (gate → tier+batch → self-host+sample), not token×n.
- [x] `USERS.md`: 5 user roles, 4 core workflows, use cases, and the automate-breadth /
      human-judgment-gates justification.
- [x] Contract tests (both sides of each boundary) — `tests/test_contracts.py`: the real
      producer emits each message, it's schema-validated, then the real consumer parses it
      (7 boundaries + schema-version pinning). Versioning + migration notes in
      `contracts/VERSIONING.md`.
- [x] ATO-style evidence packet (`ATO_EVIDENCE.md`): system categorization, authorization
      boundary + data-flow diagrams (mermaid), auth/access-control model, dependency
      inventory (4 pinned runtime deps), self-scan results (bandit 0-High + 4 triaged
      false positives, clean secret scan, ruff, 126 tests), eval evidence, and a sample
      postmortem (AF-2026-0001) + POA&M.
- [x] Baseline perf profile (`agentforge/perf.py` + `PERF_PROFILE.md`): framework
      overhead 2.8 ms/case & 0.5 MB (352 cases/s, mock target), detector 4.6 µs/op,
      regression 93 replays/s, observability 10k records ≈30–60 ms; live latency target
      p50 11.8 s + Judge ~8 s. 100-case load test → **bottleneck = sequential external
      I/O** (our code is 0.014% of wall time); fix = concurrency (~8×) + Judge-gating.
- [ ] Demo video (3–5 min) showing live attacks against the target.
- [ ] Social post tagging @GauntletAI (final only).

**Exit / final gate:** full multi-agent loop running live; all submission artifacts present.

---

## Component ownership (build vs. inherit)

| Component | Build / Inherit | Notes |
|-----------|-----------------|-------|
| Target Co-Pilot | Inherit (Week 1/2) | Only adapt for testability |
| Contracts (`/contracts`) | Build | Versioned JSON Schema, the integration seam |
| Judge Agent | Build first | Unblocks reproducible scoring |
| Red Team Agent | Build | Open/local model |
| Orchestrator | Build | Deterministic scoring core |
| Documentation Agent | Build | Gated output |
| Regression Harness | Build (deterministic) | No LLM |
| Orchestration framework | Configure (LangGraph) | State + checkpoints + retries |
| Observability | Configure (Langfuse) + custom metrics | Orchestrator's data substrate |

## Risk register (build-time)

| Risk | Mitigation |
|------|------------|
| Target not deployable in time | Fall back to Week 1 reference build early in Phase 1 |
| Frontier model refuses offensive prompts | Red Team on open/local model from day one |
| Judge unreliable → poisons everything | Ground-truth set + build Judge first, validate before scaling |
| Cost runaway during autonomous runs | Budgets + spend-rate kill-switch before Phase 5 autonomy |
| Non-reproducible regressions | Invariant-based assertions in deterministic harness, never string match |

---

## Definition of done (final)

1. Deployed target URL live, platform attacking it autonomously.
2. Five roles coordinating through versioned contracts with passing contract tests.
3. ≥3 attack categories with reproducible eval results; regression suite re-runs on change.
4. ≥3 professional vulnerability reports; critical severity human-gated.
5. Observability answers all required questions; cost analysis at 4 scale tiers.
6. Every autonomous action logged, gated, and reproducible — defensible to a hospital CISO.
