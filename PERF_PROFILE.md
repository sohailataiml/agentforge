# Performance & Load Profile — AgentForge

**Bottom line: AgentForge is I/O-bound, and the bottleneck is the sequential external
round-trips — the target's inference (~11.8 s) and the Judge's (~8 s). Our own code is
~4 orders of magnitude cheaper (2.8 ms/case).** The fix is concurrency, which pays off
almost linearly because there is essentially no CPU or memory pressure to contend for.

All numbers below are **measured** by `agentforge/perf.py` (`python -m agentforge.perf
[--live]`), not estimated. Environment: Python 3.14, Windows, single process.

## 1. Framework overhead (mock target, no Judge — free, 100 cases)

Isolates *our* code by running the full pipeline (case parse → step execution →
detector → result) against an instant mock target.

| Component | Throughput | Per-unit | Notes |
|-----------|-----------|----------|-------|
| Full eval pipeline | **352 cases/s** | **2.84 ms/case** | peak memory **0.5 MB** for 100 cases |
| Detector match | 213k ops/s | 4.6 µs/op | substring/regex over a ~600-char transcript |
| Regression replay (stub) | 93 replays/s | 10.8 ms/replay | SQLite write-bound (UPDATE+INSERT per exploit); corpora are small |
| Observability queries | — | 10,000 records in ~30–60 ms | all six queries over 10k eval records |

**Our framework is not the bottleneck by any measure.** 100 cases of pipeline work is
~0.3 s of CPU and half a megabyte of memory.

## 2. External latency (live sample)

| Call | p50 | p90 | range |
|------|-----|-----|-------|
| Target `/chat` inference | **11.76 s** | 12.43 s | 10.8–12.4 s (n=6) |
| Judge (Opus 4.8, adaptive thinking) | **~8 s** | — | 5.3–12.7 s (variance is thinking depth) |

A fully-judged case is therefore ~**11.8 s (target) + ~8 s (Judge) ≈ 20 s** of
sequential wall-clock — of which our code is **2.8 ms (0.014%)**.

## 3. 100-case load test

| Mode | Wall clock (100 judged cases) | Our-code share |
|------|-------------------------------|----------------|
| **Sequential (as-is)** | ~**33 min** (100 × ~20 s) | 0.28 s = **0.014%** |
| Detector-only (no Judge) | ~20 min (100 × ~11.8 s) | 0.28 s |
| **8-way concurrent** (projected) | ~**4 min** | negligible |
| 8-way + Judge-gated (Judge only on detector-positive/ambiguous, ~25%) | ~**2.5 min** | negligible |

### The bottleneck, named
**Sequential external network I/O** — specifically the target's LLM inference, then the
Judge's. Nothing else is close: CPU is idle between calls, memory is flat, the detectors
and DB writes are microseconds. This is the textbook profile where **concurrency is the
fix** — the work is almost entirely *waiting on other people's servers*.

### Why concurrency works here (and its ceiling)
- The pipeline is embarrassingly parallel across cases (each case is independent), and
  I/O-bound, so a thread pool or asyncio gives **near-linear speedup** with no lock
  contention — there's no shared CPU-heavy section to serialize on.
- The real ceiling is **provider rate limits**, not our machine: the single deployed
  target instance, and the Judge's Anthropic rate limit. The Orchestrator already
  handles that ceiling with **backoff → queue → abort**, so raising concurrency degrades
  gracefully instead of erroring.
- **Judge-gating** (run the deterministic detector first; call Opus only on
  detector-positive or ambiguous attempts) removes the ~8 s Judge leg from the majority
  of cases — cutting *both* latency and cost (see `AI_COST_ANALYSIS.md`, same lever).

## 4. Recommendations (in priority order)

1. **Concurrency** — run cases through a bounded worker pool (≈8, tuned to target/Judge
   rate limits). ~8× wall-clock reduction; the single highest-leverage change.
2. **Judge-gating** — skip the Judge when a deterministic detector already settles the
   case. Removes the second external leg from ~75% of cases.
3. **Regression at scale** — it's already deterministic and needs no external Judge, so
   it parallelizes trivially and stays cheap; keep it in CI.
4. Framework/CPU work needs **no optimization** — at 2.8 ms/case and 0.5 MB it will not
   be the constraint until concurrency is high enough that the providers are the wall.

## Reproduce

```
python -m agentforge.perf            # framework/CPU benches (offline, free)
python -m agentforge.perf --live     # + live target latency sample
```
