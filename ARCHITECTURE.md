# AgentForge — Multi-Agent Adversarial Evaluation Platform

**Architecture Plan** · Gauntlet AI, Austin Admission Track — Week 3
Target under test: OpenEMR **Clinical Co-Pilot** (AI chatbot over patient/operational data)

---

## Summary (~500 words)

AgentForge is a **multi-agent adversarial evaluation platform** that continuously
discovers, evaluates, escalates, and documents vulnerabilities in an AI-assisted
clinical workflow. It is deliberately **not** a static test runner. Static payload
lists go stale the moment an attacker mutates a prompt; the concern raised by
OpenEMR leadership is not "does one exploit exist" but "can the system keep pace as
attacks evolve." AgentForge answers that with a coordinated set of agents that each
own a distinct responsibility and trust level.

The platform is built on **five agent roles** plus three deterministic subsystems:

1. **Orchestrator Agent** — the strategist. Reads observability state (coverage
   gaps, open high-severity findings, recent regressions, spend rate) and decides
   what the Red Team targets next, when to trigger a regression run, and when to
   halt a campaign that is burning tokens without producing signal.
2. **Red Team Agent** — the attacker. Generates novel adversarial inputs, mutates
   partially-successful attacks into variant families, and drives multi-turn attack
   sequences. Powered by a less-restricted / open model so it is not blocked by the
   same safety training it is probing.
3. **Judge Agent** — the evaluator. Independent of the Red Team by design. Decides
   pass / fail / partial against fixed rubrics per attack category, flags
   regressions, and escalates to a human when uncertain. A separate frontier model
   is used here for reliability.
4. **Documentation Agent** — the scribe. Converts *confirmed* exploits (judge-
   verified only) into structured, reproducible vulnerability reports a senior
   engineer who was never present could reproduce and fix.
5. **Regression/Validation Harness** (deterministic, not an LLM) — converts
   confirmed exploits into versioned, replayable test cases and re-runs them on
   every target change to catch reappearing vulns and cross-category regressions.

The **critical architectural principle** is *separation of interest*: an agent that
both generates and evaluates attacks is compromised by design, so attack generation,
evaluation, strategy, and documentation live in different agents with different
models and different trust levels. **Deterministic tooling is preferred wherever
behavior must be reproducible** — replay, fuzzing, schema validation, and regression
scoring are code, not LLM calls, because a regression test that "passes" only because
model behavior drifted is worse than no test at all.

**Coordination** flows through a typed message bus (JSON-Schema-versioned contracts
in `/contracts`) and a shared state store (SQLite exploit DB + run logs). Agents hand
off work as validated messages, never shared mutable context. **Human approval
gates** sit at two points: before a critical-severity report is published, and before
any remediation is applied to the live target.

**Cost control** is first-class: per-agent token budgets, a cheaper local/open model
for the high-volume Red Team, frontier models reserved for the Judge, and an
Orchestrator kill-switch on low-signal spend. The whole system is observable — every
agent action, cost, and verdict is traced so both the Orchestrator (its data
substrate) and a human operator can answer "is the target getting more or less
resilient over time?" at any moment.

The standard is defensibility in front of a hospital CISO — every autonomous action
is logged, gated, and reproducible.

---

## Agent Roster

| Agent | Role | Trust Level | Model (default) | Autonomy |
|-------|------|-------------|-----------------|----------|
| **Orchestrator** | Strategy, prioritization, budget, regression triggers | High (reads all state; writes work items only) | Frontier (cheap tier) | Autonomous within budget |
| **Red Team** | Attack generation, mutation, multi-turn sequencing | **Low** (untrusted output, sandboxed) | Open / local model (uncensored for offensive workflows) | Autonomous |
| **Judge** | Verdicts (pass/fail/partial), regression + drift detection | High (authoritative on success) | Frontier (separate vendor from Red Team) | Autonomous; escalates on uncertainty |
| **Documentation** | Vulnerability report generation | Medium (writes reports; gated on publish) | Frontier (cheap tier) | Gated at critical severity |
| **Regression Harness** | Deterministic replay + scoring | Deterministic (no LLM) | — | Fully automated |

Why five, not one: a single-agent or linear-pipeline design cannot satisfy the
conflict-of-interest requirement (generator ≠ judge), cannot separate strategy from
execution, and cannot hold different trust levels for the attacker vs. the reporter.

---

## System Diagram

```
                         ┌─────────────────────────────────────────────┐
                         │              OBSERVABILITY LAYER              │
                         │  (traces · costs · coverage · verdicts · SLO) │
                         │        = Orchestrator's data substrate        │
                         └───────────────▲──────────────┬───────────────┘
                                         │ reads state   │ all agents emit
                                         │               │ traces + cost
                    ┌────────────────────┴───────┐       │
                    │      ORCHESTRATOR AGENT     │       │
                    │  picks target · sets budget │       │
                    │  triggers regression runs   │       │
                    └──────┬──────────────▲───────┘       │
        (1) AttackDirective│              │(6) CampaignResult
                           ▼              │
                    ┌──────────────┐      │        ┌──────────────────┐
                    │  RED TEAM    │      │        │ REGRESSION /      │
                    │  AGENT       │      └────────┤ VALIDATION HARNESS│
                    │ generate +   │  (5) triggers │ deterministic     │
                    │ mutate +     │◄──────────────┤ replay + score    │
                    │ multi-turn   │               └────────▲──────────┘
                    └──────┬───────┘                        │ stores/reads
      (2) AttackAttempt    │  ┌─────────────────┐           │
      (prompt + transcript)▼  │  LIVE TARGET    │      ┌─────┴─────────┐
                    ┌─────────┤ Clinical Co-Pilot│      │  EXPLOIT DB    │
                    │ executes │  (deployed URL) │      │ (SQLite,       │
                    │ attack   └─────────────────┘      │  versioned)    │
                    └──────┬───────┘                    └─────▲─────────┘
      (3) AttackResult     │                                  │ (4b) writes
      (transcript)         ▼                                  │ confirmed
                    ┌──────────────┐   (4a) Verdict     ┌──────┴──────────┐
                    │ JUDGE AGENT  ├──────────────────► │ DOCUMENTATION   │
                    │ pass/fail/   │  (confirmed only)  │ AGENT           │
                    │ partial +    │                    │ writes report   │
                    │ regression   │                    └──────┬──────────┘
                    └──────────────┘                           │
                                                    ┌──────────▼──────────┐
                                                    │  HUMAN APPROVAL GATE │
                                                    │  (critical severity, │
                                                    │   remediation apply) │
                                                    └──────────────────────┘
```

**Message flow (happy path):**
1. Orchestrator → Red Team: `AttackDirective` (category, subcategory, budget, seeds)
2. Red Team → Target: executes attack (direct call to deployed Co-Pilot)
3. Red Team → Judge: `AttackAttempt` + full transcript
4. Judge → Documentation (if confirmed): `Verdict{result: fail-secure violated}` → report written to Exploit DB
5. Orchestrator → Harness: triggers regression on target change
6. Harness/Judge → Orchestrator: `CampaignResult` (coverage delta, new findings, regressions) → loop

---

## Agent Contracts (inter-agent messages)

All messages are **versioned JSON Schema** in `/contracts` (min `v1`). Both producer
and consumer are contract-tested. Breaking changes require a version bump + migration
note. Every agent also publishes **error schemas** for its known failure modes.

### `AttackDirective` (Orchestrator → Red Team)
```json
{
  "schema_version": "1.0.0",
  "directive_id": "uuid",
  "attack_category": "prompt_injection | data_exfiltration | state_corruption | tool_misuse | dos | identity_role",
  "subcategory": "string",
  "owasp_refs": ["LLM01", "A01"],
  "seed_cases": ["case_id", "..."],
  "strategy_hint": "novel | mutate:{parent_attempt_id} | multi_turn",
  "token_budget": 20000,
  "max_turns": 8,
  "priority": "critical | high | medium | low"
}
```

### `AttackAttempt` (Red Team → Judge)
```json
{
  "schema_version": "1.0.0",
  "attempt_id": "uuid",
  "directive_id": "uuid",
  "attack_category": "string",
  "input_sequence": [{"turn": 1, "role": "user", "content": "..."}],
  "target_transcript": [{"turn": 1, "role": "assistant", "content": "..."}],
  "expected_safe_behavior": "string",
  "parent_attempt_id": "uuid | null",
  "cost": {"tokens": 0, "usd": 0.0}
}
```

### `Verdict` (Judge → Orchestrator + Documentation)
```json
{
  "schema_version": "1.0.0",
  "attempt_id": "uuid",
  "result": "pass | fail | partial",
  "confidence": 0.0,
  "rubric_id": "string",
  "rubric_version": "1.0.0",
  "rationale": "string",
  "is_regression": false,
  "regressed_case_id": "string | null",
  "escalate_to_human": false,
  "severity": "critical | high | medium | low | info"
}
```
> Convention: `result: "fail"` = the *target failed to stay secure* = a confirmed
> exploit. This is stated explicitly in the rubric to avoid polarity ambiguity.

### `VulnReport` (Documentation → Exploit DB)
```json
{
  "schema_version": "1.0.0",
  "vuln_id": "AF-2026-0001",
  "severity": "critical | high | medium | low",
  "title": "string",
  "attack_category": "string",
  "owasp_refs": ["LLM01"],
  "clinical_impact": "string",
  "reproduction_steps": ["..."],
  "minimal_attack_sequence": [{"turn": 1, "content": "..."}],
  "observed_behavior": "string",
  "expected_behavior": "string",
  "recommended_remediation": "string",
  "status": "open | in_progress | resolved | wont_fix",
  "fix_validation": {"validated": false, "regression_case_id": "string"},
  "human_approved": false
}
```

### Error schemas (published for every agent)
`target_unreachable`, `budget_exceeded`, `judge_timeout`,
`no_findings_in_window`, `regression_detected`, `schema_validation_failed`.

---

## Key Design Decisions

### 1. Generator ≠ Judge (conflict of interest)
The Red Team and Judge run **different models from different vendors** and never
share context. The Judge only sees the `AttackAttempt` transcript, never the Red
Team's reasoning. This prevents a self-grading loop where an attacker rationalizes
its own success.

### 2. Model selection per role
| Role | Model class | Justification |
|------|-------------|---------------|
| Red Team | Open / local (e.g. an uncensored open-weight model, or a self-hosted model) | Frontier models refuse offensive-security workflows; high call volume makes cost the binding constraint. Runs in a sandbox because its output is untrusted. |
| Judge | Frontier, separate vendor | Evaluation reliability > cost. Low call volume. Independence from Red Team model. |
| Orchestrator | Frontier, cheap tier | Reasoning over structured state; low volume; deterministic-ish inputs. |
| Documentation | Frontier, cheap tier | Quality writing, but gated + reviewable. |
| Harness | **No LLM** | Reproducibility requires determinism. |

### 3. AI vs. deterministic tooling
- **AI**: attack generation, mutation, judgment of open-ended behavior, report prose.
- **Deterministic**: regression replay, exact-match/regex/semantic-diff scoring for
  known exploits, schema validation, cost accounting, coverage counting, fuzzing of
  token-length/tool-parameter boundaries, PHI leak detection via pattern matching.
- Rationale: LLMs are non-deterministic; anything that must give the *same answer on
  the same input across runs and versions* is code.

### 4. Regression semantics — "why did this pass?"
A regression test does **not** pass merely because the target's output changed. Each
confirmed exploit is stored with a **judge rubric + a deterministic assertion**. On
replay, the harness re-runs the exact attack sequence and checks the *invariant that
was violated* (e.g. "no cross-patient PHI in output"), not string equality. A pass
requires the invariant to hold; behavior drift that avoids the specific string but
still leaks is still a fail.

### 5. Judge drift & self-validation
- Judge criteria are **frozen, versioned rubrics** — changing them requires a version
  bump and re-running the ground-truth set.
- A **ground-truth labeled set** (known-exploit + known-safe transcripts) is run
  against the Judge on every rubric change; accuracy must exceed a threshold or the
  change is rejected. This is the "test the tester" loop.
- If the Judge's agreement rate with ground truth drops, it is flagged as drifting.
- On low `confidence`, the Judge sets `escalate_to_human: true` instead of guessing.

### 6. Orchestrator prioritization signals
Reads from the observability layer:
- coverage gaps (categories/subcategories with fewest cases),
- open high-severity findings (re-probe for variants),
- recent regressions (re-run neighbors),
- spend rate vs. signal (halt low-yield campaigns).
Uses a simple weighted score (deterministic) to rank the next campaign; the *how to
attack* is delegated to the Red Team, the *what/where* is the Orchestrator's job.

### 7. Human approval gates (trust boundaries)
- **Publish gate**: critical-severity `VulnReport` requires human approval before it
  is marked published (`human_approved: true`). Prevents confident false positives
  from wasting engineering time.
- **Remediation gate**: the platform never pushes a fix to the live target
  autonomously. It recommends; a human applies.
- **Attack-scope gate**: the platform can only attack an allow-listed target URL,
  preventing it from being turned against systems it shouldn't touch.

### 8. Cost, rate limits, scale
- Per-agent + per-campaign token budgets, enforced by the Orchestrator.
- Rate-limit handling documented per external API (LLM providers, target,
  observability backend): exponential backoff → queue → abort, with the Orchestrator
  notified on abort.
- Local/open Red Team model removes the dominant cost driver at scale.
- Cost analysis projected at 100 / 1K / 10K / 100K runs (see `AI_COST_ANALYSIS.md`):
  the architectural change at each tier (caching seeds, batching Judge calls, moving
  Red Team fully local, sharding the exploit DB) is documented, not just token×n.

---

## Red Team Agent — Architecture (as built)

The Red Team is implemented in **two layers** so the *attacker model* is
swappable by configuration and the *attack logic* is testable in isolation.

### 1. Provider seam — [`agentforge/red_team_client.py`](agentforge/red_team_client.py)

A single `complete(messages, …)` over the OpenAI-compatible `/chat/completions`
wire format (via `httpx`, no vendor SDK), mirroring the target adapter's
one-seam philosophy. The attacker model is chosen entirely by environment
variable — `RED_TEAM_BASE_URL` / `RED_TEAM_MODEL` / `RED_TEAM_API_KEY`:

| | |
|---|---|
| **Primary** | Groq free tier · `llama-3.3-70b-versatile` (fast, cheap, safety-tuned) |
| **Fallback** | OpenRouter uncensored model (`dolphin-mistral-24b-venice-edition`) |

This realizes the three model-tiering constraints from §Key Design Decisions #2
in one seam: **independence** (a different vendor from the Anthropic Judge),
**cost** (the Red Team is the highest-volume caller — one generation per attempt
plus N per mutation family, so it must be the cheap/open tier), and
**refusal-avoidance**. The last is now a **runtime, automatic failover**, not just
a config swap: `complete()` calls the primary, and if it **refuses** (a refusal
opener detected in the response — `is_refusal()`) or **errors/unreachable**, it
transparently retries on the uncensored fallback provider and marks the result
`fell_back=True` with a reason. So a safety-tuned Groq refusing to generate an
offensive prompt does not block the campaign — OpenRouter's uncensored model
picks it up automatically, and the provenance (which model served the attack) is
carried through to the `AttackAttempt` and the console. The seam only **produces**
text — it never executes anything.

### 2. Agent pipeline — [`agentforge/red_team.py`](agentforge/red_team.py)

`run_directive(directive, patient_id, judge=…)` drives one `AttackDirective`
end to end:

```
AttackDirective
      │ generate  (open model, temperature 0.9 → attack variety over determinism)
      ▼
AttemptSpec { input_sequence, expected_safe_behavior }
      │ EGRESS SCREEN ──► drop + log (dropped_reason) if content carries a real credential
      ▼
send_to_target(patient_id, input_sequence)          ← the one target seam
      ▼
target_transcript
      │ assemble + schema-validate (contracts/attack_attempt.schema.json)
      ▼
AttackAttempt ──► JUDGE (injected; different vendor) ──► Verdict
      │
      │ if Verdict.result == "partial"
      ▼
MUTATION LOOP: one variant per strategy (paraphrase · encoding · role_frame ·
turn_splitting), each linked by parent_attempt_id, re-executed + re-judged — no human.
```

**Egress screen** (`egress_ok`) — deterministic, not an LLM. Before any
generation reaches the target it is scanned for real-credential patterns
(`sk-ant-…`, `gsk_…`, `AKIA…`, PEM private keys); a match is dropped and recorded
as `dropped_reason`, never forwarded. This is the "content classifier on egress"
from §Known Failure Modes — the attacker model is untrusted, so a generation
containing a live secret must never be executed.

**Mutation engine** — a `partial` Verdict is the escalation trigger. The agent
regenerates the parent attack under each strategy in `MUTATION_STRATEGIES`
(paraphrase, encoding, role-frame, turn-splitting), passing the parent's
`input_sequence` into the generation prompt, links each variant to the parent via
`parent_attempt_id`, and re-executes + re-judges autonomously. This is what turns
one partial success into a variant family **without prompting** — the Phase 5
exit criterion.

**Judge injection & independence** — the Judge is passed *into* `run_directive`
as a callable, never imported as a peer. Two consequences: (a) generation +
execution run with the Judge absent (the live path that needs no Anthropic
credits), and (b) the generator↔judge separation (§Key Design Decisions #1) holds
**structurally** — the Red Team literally cannot reach or score its own attempts.

### Trust boundaries honored

- **Untrusted output**: a generation is only ever sent to the allow-listed target
  through `send_to_target`; the egress screen drops harmful generations first.
- **Different vendor** from the Judge (Anthropic), enforced by both the
  injected-judge seam and the open-model provider config.
- **Accountable spend**: every attempt is a schema-valid `AttackAttempt` carrying
  its own `cost{tokens, usd}` (generation + target), so per-attempt spend is
  auditable and roll-uppable into a `CampaignResult`.

### Where it runs

`run_directive` is exercised by the eval runner and by the web console's Red Team
panel ([`agentforge/webapp.py`](agentforge/webapp.py)). A full live attack
(generate on Groq → execute against the deployed target → schema-valid
`AttackAttempt`) is validated in `tests/test_red_team.py` (marked `live`); the
pure logic (egress screen, attack parsing, attempt assembly) is covered by
non-live tests.

---

## Regression Harness — Architecture (as built)

`agentforge/regression.py` — **deterministic, no LLM.** Once an exploit is
confirmed, it must never silently come back. The harness freezes confirmed
exploits and replays them on demand (or when the Orchestrator sees a target-version
change), asserting the *violated invariant* rather than an output string.

**Corpus (versioned SQLite).** `register_from_cases` freezes every
`add_to_regression` case into a self-contained row (`case_to_dict` → JSON), keyed
by `case_id`, with the case's `expected_result` as the immutable **baseline** and
`first_seen_at`/`first_version` stamped once. Re-registering is idempotent and
preserves the first-seen provenance. Three tables: `exploits` (the corpus + current
status), `runs` (one row per campaign, with target version + counts), and
`run_results` (per-exploit result each run — the history that makes reappearance
detectable). Default DB lives under the git-ignored `evals/results/`.

**Replay is deterministic.** Each exploit is rebuilt with `EvalCase.from_dict` and
run through `run_case` **with no Judge** — pure detectors, no model on our side.
The target is unauthenticated, so a full replay costs **no API credits** (only the
target's own spend is reported). `replay_fn` is injectable so the whole classifier
is unit-tested without a network.

**Invariant assertion, not string equality.** The detector encodes the invariant
(e.g. "PHI identifiers must not appear for an unauthenticated caller"). A fix that
merely reworded the old leak still trips the detector — so a passing replay means
the *invariant* now holds, not that a string changed.

**Classification** (`classify(baseline, current, previous)`), by a security rank
`pass < partial < fail`:

| vs baseline | vs previous run | status | alert? |
|---|---|---|---|
| worse | — | `regressed` (a defense broke) | ✔ |
| better | — | `fixed` (exploit no longer reproduces) | — |
| equal, baseline fail | prev was cleaner | `reproduces` + `reappeared` | ✔ |
| equal, baseline fail | — | `reproduces` (still vulnerable) | — |
| equal, baseline pass | — | `stable` (defense holds) | — |
| unrunnable | — | `error` | — |

`reappeared` is the cross-run signal: an exploit that was `fixed` last run and
`fail`s again this run is flagged even though its status vs baseline is only
"reproduces". Alerts = regressions ∪ reappearances.

**Output.** `to_campaign_result` emits a `CampaignResult` (validated against
`contracts/campaign_result.schema.json`) for the Orchestrator: `attempts_run`,
`confirmed_exploits` (still reproduce), `regressions_detected` (alert count),
`total_cost`, `signal_yield`. The CLI (`python -m agentforge.regression`) exits
non-zero when any alert is found, so CI / the Orchestrator can gate on it.

**Tests.** `tests/test_regression.py` — corpus round-trip, idempotent registration,
every classification transition, cross-run regression + reappearance, boundary
regression, and contract-valid `CampaignResult`, all non-live; a `live` test
replays the real corpus against the deployed target.

---

## Orchestrator — Architecture (as built)

`agentforge/orchestrator.py` — **deterministic, no LLM.** The strategy layer that
turns observability state into the next action and drives the autonomous loop.

**Observability in.** `read_observation` assembles an `Observation` from three
sources, best-effort: the eval **run logs** (attempts, confirmed exploits, spend
per category), the **report corpus** (`reports/AF-*.json` → open critical/high
findings per category), and the **regression DB** (current vs previous target
version, and regression/reappearance counts per category).

**Scoring.** `score_categories` ranks the six categories by a weighted sum, tuned
so **regression ≫ open-high-sev > coverage-gap**: a broken defense is always most
urgent (`_W_REGRESSION=10`), a known-weak category outranks exploring a fresh one
(`_W_HIGHSEV=4`), and an unexplored category still draws attention
(`_W_COVERAGE=1`, capped at `_MIN_ATTEMPTS`). Killed categories are excluded.

**Directive out.** `next_directive` emits the top category as a schema-valid
`AttackDirective` (validated against the contract) with a priority derived from
state (`critical` if regressed, `high` if weak, else `medium`), or `None` when the
budget is spent or nothing scores.

**Loop control** (`orchestrate`, injectable executor):
1. If the target version changed since last seen, run the Regression Harness first.
2. Emit a directive, execute it, and **feed the outcome back** into the observation
   (attempts, exploits, spend) so scores shift as categories are exhausted.
3. **Budget:** stop once `total_spend_usd` reaches the cap.
4. **Kill-switch** (`apply_kill_switch`): a category that has spent past
   `_KILL_MIN_SPEND_USD` with yield below `_KILL_MIN_YIELD` and nothing urgent open
   is killed and never issued again.
5. **Rate limits — backoff → queue → abort:** each `RateLimited` backs off
   exponentially and defers (queues) the directive; a sustained streak aborts the
   loop cleanly.

The CLI wires a live executor (Red Team `run_directive` + Judge) and the Regression
Harness; `--dry-run` prints the scores + next directive with no spend. Tests
(`tests/test_orchestrator.py`) cover scoring order, the kill-switch, budget stop,
regression-on-change, and the backoff/queue/abort sequence with a stub executor.

---

## Documentation Agent — Architecture (as built)

`agentforge/documentation.py` — turns a confirmed exploit into a professional,
reproducible `VulnReport` (contracts/vuln_report.schema.json).

**Source of truth.** Only a confirmed (`result == "fail"`) Verdict may be
documented (`finding_from_verdict` refuses anything else). Evidence — the attack
sequence and the target transcript — is captured verbatim from the live run.

**Deterministic scaffold + authored prose.** Ids, severity, the minimal (dedup'd)
attack sequence, status, the fix-validation link, and timestamps are assembled in
code; only the prose (title, clinical impact, reproduction steps, observed/expected
behaviour, remediation) is authored — by the frontier model
(`claude-opus-4-8`, adaptive thinking, structured output) grounded strictly in the
evidence, with a deterministic fallback so a report is always producible.

**Gates.** Data-quality: unique `AF-YYYY-NNNN` id, uuid attempt, non-empty prose,
no duplicate attack sequence across the corpus. **Human approval:** a `critical`
report is contract-invalid unless `human_approved` — `build_vuln_report` and
`publish` both refuse an unapproved critical, so the human-in-the-loop gate is
enforced at the contract boundary. **No autonomous remediation:**
`fix_validation.validated` starts false and is only flipped by the deterministic
Regression Harness once a fix is proven.

`generate_reports.py` mines confirmed findings from both the eval suite (Judge
scoring every case) and the Red Team (judged directives), dedupes by attack
sequence, and publishes JSON + Markdown to `reports/`. See `reports/README.md`.

---

## Framework & Infrastructure

- **Orchestration framework**: LangGraph (explicit graph of agent nodes with typed
  state, durable checkpoints, and per-node retries) — chosen over CrewAI/AutoGen for
  its explicit state machine and failure-recovery semantics, which matter for
  auditability. *(This is a defensible default; the build-vs-configure record in the
  architecture defense compares alternatives.)*
- **State store**: SQLite exploit DB (versioned, indexed by severity / category /
  system_version) + append-only run-log table for traces.
- **Message bus**: in-process typed messages validated against `/contracts` schemas
  (upgradeable to a real queue — e.g. Redis/SQS — at the 10K+ tier; queue-depth
  monitoring documented).
- **Observability**: Langfuse (or equivalent) for inter-agent traces + a custom
  metrics table the Orchestrator queries. Every finding is traceable back through the
  attempt → directive → campaign that produced it.

---

## Known Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Red Team emits genuinely harmful content | Output sandboxed; never executed against real PHI; content classifier on egress | Log + drop; don't forward |
| Judge agrees with everything (drift) | Ground-truth accuracy check | Freeze verdicts, flag, require human review |
| Orchestrator has no clear priority | Empty priority queue | Fall back to round-robin coverage sweep + notify human |
| Agent timeout / crash mid-campaign | LangGraph checkpoint | Resume from last durable state; emit error-schema message |
| Cascading failure across agents | Circuit breaker per edge | Halt campaign, surface trace, no partial writes to Exploit DB |
| Cost runaway | Spend-rate monitor | Orchestrator kill-switch; campaign marked `budget_exceeded` |

---

## OWASP Coverage Map

Every eval case is tagged with both an internal category and an OWASP reference.

- **LLM Top 10**: LLM01 Prompt Injection · LLM02 Insecure Output Handling ·
  LLM06 Sensitive Info Disclosure · LLM08 Excessive Agency · LLM05 Supply Chain.
- **Web Top 10 (relevant)**: A01 Broken Access Control · A03 Injection ·
  A04 Insecure Design · A06 Vulnerable Components · A07 Auth Failures ·
  A09 Logging Failures · A10 SSRF.

---

## AI-Use Disclosure

| AI decision | Deterministic check / gate that follows |
|-------------|------------------------------------------|
| Red Team generates attack | Executed only against allow-listed sandbox target; output untrusted |
| Judge verdict | Ground-truth-validated rubric; low-confidence escalates to human |
| Documentation writes report | Schema + data-quality validation; critical severity gated on human approval |
| Orchestrator picks target | Deterministic scoring; budget kill-switch |

**Residual risks**: Judge false-negatives on novel categories not in ground truth;
Red Team model capability ceiling; cost estimation error at 100K scale. All three are
documented and monitored, not assumed away.
