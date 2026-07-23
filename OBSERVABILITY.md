# Observability — AgentForge

Every question a security lead or CISO needs to ask about the platform is answerable
from state the agents **already write** — no separate telemetry pipeline. Three
artifacts are the substrate:

| Source | Written by | Carries |
|--------|-----------|---------|
| `evals/results/run-*.jsonl` | Eval Runner | one `eval_result` per case: category, result, `target_system_version`, `executed_at`, cost, and the Judge `verdict` (with `judged_at`, severity, rubric) when scored |
| `evals/results/regression.db` | Regression Harness | `runs` (version, checked, reproduces, regressed, `started_at`) + per-exploit `run_results` |
| `reports/AF-*.json` | Documentation Agent | `VulnReport`s: severity, status, category, `created_at`, approval |

Two front ends read this substrate:

- **Web console** (`https://agentforge-console.onrender.com`) — the live dashboard:
  tiles, results-by-category, the regression panel, and the Orchestrator's scoring.
- **Headless CLI** — `python -m agentforge.observability` prints the full text
  dashboard; the functions in `agentforge/observability.py` are the queries, tested in
  `tests/test_observability.py`.

## The six required questions

### 1. Cases per category
`cases_per_category(records)` — a count of attempts per attack category. *Console:*
"categories" tile + Results-by-category. *CLI:* first block.

### 2. Pass/fail rate by category **and** system version
`pass_fail_by_category_version(records)` — keyed by `category @ target_system_version`,
with a **resilience_rate** = pass / (pass+fail+partial); errors are excluded from the
rate. Because each record stamps `target_system_version`, the same category can be
compared **across target releases** — the core "did this get better or worse?" query.

### 3. Resilience trend over time
`resilience_trend(regression_runs)` — one row per regression run:
`reproduces/checked` confirmed exploits still landing, and `resilience = 1 −
reproduces/checked`, ordered by `started_at`. Rising resilience across versions = the
target is getting harder; a non-zero `regressed` = a defense broke. *Console:*
Regression panel tiles across runs.

### 4. Open / in-progress / resolved vulnerabilities
`vuln_status(reports)` — counts by `status` (open, in_progress, resolved, wont_fix) and
by severity, plus `open_high_or_critical` (the number that should keep someone up at
night). Driven by the `status` field each `VulnReport` carries.

### 5. Run cost + scaling rate
`cost_summary(records)` — total USD/tokens, `per_case_usd`, and a naive
`projected_usd_per_1k`. The naive projection is intentionally linear; the *architected*
scaling (where the curve bends and why) is in [`AI_COST_ANALYSIS.md`](AI_COST_ANALYSIS.md).

### 6. Per-agent action timeline
`agent_timeline(records, reports, runs)` — a chronological who-did-what-when,
**reconstructed from the timestamp each agent stamps on its own output** (no separate
event bus): Eval Runner (`executed_at`), Judge (`verdict.judged_at`), Documentation
(`created_at`), Regression (`started_at`). This is what makes an autonomous run
**auditable** — every action is attributable to an agent, ordered, and reproducible.

## Example (live data)

```
$ python -m agentforge.observability
=== pass/fail by category & target version ===
  data_exfiltration @ 0.15.8   pass=1 fail=1 ... resilience=0.5
  prompt_injection  @ 0.15.8   pass=1 fail=0 ... resilience=1.0
=== vulnerability status ===
  by status:   {'open': 4, 'in_progress': 0, 'resolved': 0, 'wont_fix': 0}
  by severity: {'critical': 3, 'high': 1}
  open high/critical: 4  |  total: 4
=== run cost + scaling ===
  5 cases | $0.13 | 29,463 tokens | $0.027/case | ~$27/1k naive
=== per-agent action timeline (most recent) ===
  2026-07-21T14:59:27  [Eval Runner  ] ran data-exfil-unauthenticated-phi-retrieval -> fail
  2026-07-23T01:42:00  [Documentation] authored AF-2026-0001 [critical]
```

## Design note

There is deliberately **no separate observability datastore to keep in sync** — the
answers are derived from the same contract-validated artifacts the agents produce, so
the dashboard can never drift from what actually happened. Adding a new metric is a new
query over existing records, not a new write path.
