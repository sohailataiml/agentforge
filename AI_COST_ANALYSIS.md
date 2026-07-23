# AI Cost Analysis — AgentForge

How much AgentForge costs to run, where the money actually goes, and — the part that
matters — **the architectural change each order-of-magnitude of scale forces**. The
headline: naive cost is linear in LLM calls, but the curve bends at every tier because
the one expensive component (the frontier Judge) is the one we can increasingly *avoid
calling*.

All figures are **measured from this project's own runs** (token usage reported by each
provider), not hand-waved token×price estimates. Model prices: Opus 4.8 $5/$25 per 1M
in/out; Groq `llama-3.3-70b` ≈ $0.59/$0.79 per 1M; OpenRouter `dolphin-mistral-24b` ≈
$0.20/$0.20 per 1M.

## 1. What one attack actually costs us

An end-to-end adversarial attempt has four steps. Only two of them cost *us* money —
the Red Team generation and the Judge. (The target's own inference is billed to whoever
operates the target; we surface it for transparency but it isn't AgentForge's spend.)

| Component | Model | Our cost / call | Share of our cost |
|-----------|-------|-----------------|-------------------|
| Red Team generation | Groq `llama-3.3-70b` (open) | ~$0.001 | ~2% |
| Red Team fallback (on refusal) | OpenRouter `dolphin-mistral-24b` | ~$0.002 | rare |
| Target execution | target's own model | ~$0.027 *(target-side, not ours)* | — |
| **Judge verdict** | **Opus 4.8 (adaptive thinking)** | **~$0.055** | **~95%** |
| Deterministic detector | none (code) | $0.000 | 0% |
| Regression replay | none (code) | $0.000 | 0% |
| Documentation (per confirmed exploit) | Opus 4.8 | ~$0.05 | only on a `fail` |
| Orchestrator scoring | none (code) | $0.000 | 0% |

**Measured anchors:** a full deterministic eval/regression pass over the 5-case corpus
cost **$0.134** (~$0.027/case, entirely target-side — zero LLM spend on our side). One
orchestrator-driven Red-Team-generate + execute + **Judge** attempt cost **$0.088**, of
which the Opus Judge was the overwhelming majority.

**The one fact that governs everything below: the frontier Judge is ~95% of our
per-attempt cost.** Red Team generation is nearly free (open model), and the two most
valuable safety nets — the deterministic detectors and the whole Regression Harness —
cost **nothing** because they run in code, not in a model.

### Measured development spend

Across all development (building rubrics, the 12-case Judge accuracy harness, report
generation, and dozens of live Red Team + Orchestrator runs), **our total Opus spend was
under ~$5**. The deterministic layers (eval detectors, regression, orchestrator scoring)
were run far more often than the Judge and added nothing.

## 2. Defining a "run"

A **run = one end-to-end adversarial attempt** (generate → execute → judge), the atomic
unit the numbers below scale. Naive cost per run ≈ **$0.056** (Groq gen + Opus Judge).
A "campaign" is many runs; a nightly regression pass is *runs at $0 marginal LLM cost*.

## 3. Projections — and why they aren't token×n

The naive column is honest linear scaling ($0.056 × runs). The **architected** column is
what you actually pay once you make the change that tier forces. The changes are all
variations on one theme: **stop paying Opus to look at attempts a cheaper stage already
settled.**

| Scale | Naive (Judge every run, Opus) | Architected | The change this tier forces |
|-------|-------------------------------|-------------|------------------------------|
| **100 runs** | **$5.60** | **$5.60** | None. Judge-every-attempt is fine; simplicity wins. |
| **1,000 runs** | $56 | **~$14** | **Gate the Judge.** Run the deterministic detector first; call Opus only on detector-positive or ambiguous attempts (~25% here). Prompt-cache the frozen rubric (system prompt) so repeat input is ~90% cheaper. |
| **10,000 runs** | $560 | **~$70** | **Tier + batch the Judge.** Haiku 4.5 pre-filters ($1/$5 vs $5/$25 — ~5× cheaper); Opus confirms only the borderline minority. Route non-urgent judging through the Batch API (−50%). Regression (the bulk of repeat volume) stays $0 — it's deterministic. |
| **100,000 runs** | $5,600 | **~$350** | **Self-host + sample.** Move the bulk Judge to an open-weight model on owned/spot GPUs (marginal ≈ electricity); reserve Opus for a *statistically sampled* audit slice + all critical/escalated verdicts. Shard the Orchestrator; async queue with backpressure. |

The curve bends from **~$0.056/run → ~$0.0035/run** (16× cheaper) not by discounts but
by **architecture**: each tier moves more traffic off the frontier model onto a
deterministic, cached, tiered, batched, or self-hosted path — and the highest-volume
activity of all (regression replay) never touches a model.

## 4. How the platform already controls cost (built, not aspirational)

- **Deterministic-first.** Every eval case has a code detector; the Judge is the
  *authority* only where semantics matter. The Regression Harness and Orchestrator
  scoring are pure code — **$0 LLM cost at any volume.**
- **Model tiering by job.** The Red Team runs on an open model (Groq, with an
  uncensored OpenRouter fallback) — cheap *and* refusal-resistant. The frontier model is
  reserved for the Judge and Documentation, where reasoning quality is the product.
- **Orchestrator budget + kill-switch.** The autonomous loop enforces a hard spend cap
  and trips a per-category kill-switch when signal-yield (exploits per dollar) drops —
  so money flows to where attacks actually land, not into low-signal categories.
- **Regression is free to repeat.** The most-run activity in a mature program (re-proving
  fixes on every target change) is deterministic replay — no credits, so it can run in
  CI on every deploy.
- **Provider-agnostic seam + backoff→queue→abort.** The OpenAI-compatible client lets us
  swap to whatever model is cheapest per tier without touching agent logic, and the
  rate-limit handling avoids paying for retries that would fail anyway.

## 5. Honest caveats

- Opus adaptive-thinking output tokens dominate Judge cost and vary with attempt
  complexity; the ~$0.055 anchor is an average, not a cap.
- Prompt-cache and Batch-API savings assume steady-state volume; a cold, bursty workload
  sees less.
- Target-side inference cost is real but out of AgentForge's ledger — it belongs to the
  system under test.
- Self-hosting at 100K only pays off past a utilization threshold; below it, the Batch
  API on a frontier model is cheaper than idle GPUs.
