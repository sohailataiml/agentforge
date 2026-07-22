# Application Flows

How a request actually moves through AgentForge, as of Phase 5. There is no
single pipeline yet — there are **two independent flows**, and they only
share two things: the target adapter (`send_to_target`) and the Judge.
Understanding them separately, then seeing where they overlap, is the
clearest way to hold the whole system in your head.

Pairs with [ARCHITECTURE.md](ARCHITECTURE.md) (the intended five-role design)
and [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) (what's built vs. not).

---

## Flow A — the authored eval suite (Phase 3 + 4)

"Run the cases we already wrote and see if they still hold."

```
evals/cases/**/*.yaml
       |  (human-authored: attack + detector, before anything runs)
       v
agentforge/eval_case.py         load_all_cases()
       |  parse YAML -> validate against eval_case.schema.json -> EvalCase objects
       v
agentforge/eval_runner.py       run_case() / run_suite()
       |  for each step: send_to_target(...) ------> LIVE TARGET (Render)
       |  grade with step.detector.outcome(transcript)   [deterministic]
       |  IF case.requires_judge (or judge_all): -------> agentforge/judge.py
       |        judge_attempt() overrides the detector's guess, authority="judge"
       v
EvalResult  (per contracts/eval_result.schema.json)
       |  write_results_jsonl()
       v
evals/results/run-<timestamp>.jsonl
       |
       v
evals/dashboard.py   build()  ->  evals/results/dashboard.html
       (or the webapp's /api/console-body, same renderer)
```

**Entry point:** `python -m evals.run` (or the webapp's "Run attack suite"
button — literally the same `run_suite()` call in a background thread, see
`webapp.py:_do_run`).

**The one branch that matters:** not every case invokes the Judge. Only
cases marked `requires_judge: true` get a Judge call (unless `judge_all=True`
is passed), because most cases — like the cross-patient session-bleed case —
have a detector crisp enough that a Judge call would just cost money for no
better signal.

---

## Flow B — the Red Team campaign (Phase 5)

"Invent a new attack right now and see what happens." No case file involved.

```
build_directive(category, subcategory, owasp_refs, ...)
       |  (stand-in for Phase 6's Orchestrator -- a plain function call for now)
       v
AttackDirective  (per contracts/attack_directive.schema.json)
       |
       v
agentforge/red_team.py          run_directive(directive, patient_id, judge=...)
       |
       +--> generate_attempt_spec()
       |        |  builds a system prompt framing the attack goal
       |        v
       |   agentforge/red_team_client.py   complete()
       |        |  POST to Groq (or OpenRouter) -- the OPEN, untrusted attacker model
       |        v
       |   raw text  ->  _parse_attack()  ->  AttemptSpec (input_sequence + expected_safe_behavior)
       |
       +--> egress_ok(spec)   <- deterministic secret-pattern screen
       |        |  fail -> dropped, never sent (AttemptRecord.dropped_reason set)
       |        v  pass
       +--> send_to_target(...) ------------------------> LIVE TARGET (Render)
       |
       +--> _assemble_attempt()  ->  AttackAttempt (schema-validated against attack_attempt.schema.json)
       |
       +--> IF judge is not None:
                agentforge/judge.py   judge_attempt()  ->  Verdict
                        |
                        v
              IF verdict.result == "partial":
                   for strategy in (paraphrase, encoding, role_frame, turn_splitting):
                        generate_attempt_spec(parent=spec, strategy=strategy)  <- MUTATE
                        (repeat: generate -> screen -> execute -> judge, linked by parent_attempt_id)
       v
Campaign  { directive_id, attack_category, records: [AttemptRecord, ...] }
```

**Entry point:** called directly in Python (see `tests/test_red_team.py`), or
via the webapp's "Generate & attack" button (`webapp.py:red_team()` ->
`run_directive(directive, patient_id)`).

**Note:** the console's ad-hoc button calls `run_directive` with no `judge`
argument — a click there generates and executes an attack and shows the raw
transcript, but does **not** score it or trigger mutation. The mutation loop
only fires when a caller explicitly passes a `judge` callable; that's
currently a Python-level integration, not yet exposed as a webapp option.

---

## Where the two flows are identical

Both eventually call the exact same `send_to_target(session_id, messages,
patient_id)` from Phase 1 — Flow A drives it from a YAML step, Flow B drives
it from a freshly-generated `AttemptSpec`. Everything downstream of "the
target replied" (schema validation, cost accounting, scoring) is built once
and reused, not duplicated.

Both flows can also hand their result to the *same* `judge_attempt()`
function — Flow A gets `authority="judge"` on an `EvalResult`; Flow B gets a
`Verdict` attached to an `AttemptRecord`. One Judge, two callers.

---

## What's still a stand-in, not a real agent

`build_directive()` in `red_team.py` is doing the Orchestrator's job by hand
right now — a category is picked and the function is called directly (by a
test, or the webapp). There is no code yet that reads observability state,
decides *which* category needs attention next, enforces a token budget
across a whole session, or produces a `CampaignResult`
(`contracts/campaign_result.schema.json` — `attempts_run`,
`confirmed_exploits`, `signal_yield` for a kill-switch) to close the loop.
That contract has existed since Phase 0, but nothing populates it yet —
that's Phase 6.

Similarly, there is no Documentation Agent turning a confirmed `Verdict`
into a `VulnReport` yet (Phase 7), and no deterministic Regression Harness
replaying confirmed exploits on every target change (also Phase 6). Right
now "regression" is just a boolean flag (`add_to_regression: true`) sitting
on a case file, waiting for something to act on it.

---

## Summary

| | Flow A — eval suite | Flow B — Red Team campaign |
|---|---|---|
| Attack source | hand-authored YAML (`evals/cases/`) | generated live by an open model |
| Answers | "did anything we already know about regress?" | "is there something we don't have a case for yet?" |
| Judge use | only if `requires_judge` / `judge_all` | only if a `judge` callable is passed in |
| Self-mutation | no | yes, on a `partial` verdict |
| Entry point | `python -m evals.run`, webapp "Run attack suite" | direct call, webapp "Generate & attack" |

Neither flow yet feeds a real Orchestrator, Regression Harness, or
Documentation Agent — those three are the remaining work in
[IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) (Phases 6–7).
