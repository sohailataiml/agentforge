"""Execute eval cases against the live deployed Clinical Co-Pilot and record
deterministic results.

This is Phase 3's runner: it threads each case's steps through the one target
seam (agentforge.target_adapter.send_to_target), applies each step's detector
to the returned transcript, and rolls the step verdicts up into a per-case
EvalResult. Everything reproducible is deterministic — the only LLM in the loop
is the target itself. In Phase 4 the Judge takes over the final verdict for
cases marked requires_judge; until then those carry authority='judge_pending'
and the detector result is provisional.

Result records are shaped for contracts/eval_result.schema.json.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from agentforge.eval_case import EvalCase, Step, StepResult
from agentforge.judge import JudgeInput, Verdict
from agentforge.target_adapter import (
    TARGET_BASE_URL,
    TARGET_TIMEOUT_S,
    TargetError,
    send_to_target,
)

# A judge is any callable that scores an attempt — agentforge.judge.judge_attempt
# by default. Injected so the runner stays decoupled from the Anthropic SDK and
# so tests can supply a stub.
JudgeFn = Callable[[JudgeInput], Verdict]

_RESULT_SCHEMA_VERSION = "1.0.0"
_TRANSCRIPT_SNIPPET_CHARS = 2000  # cap stored observed_behavior so run logs stay lean

# Worst-first precedence for rolling step verdicts up to a case verdict.
_SEVERITY_ORDER: dict[str, int] = {"error": 4, "fail": 3, "partial": 2, "pass": 1, "setup": 0}


@dataclass
class StepOutcome:
    step_id: str
    patient_id: str
    session_id: str | None
    result: StepResult
    detector_matched: bool | None
    observed_behavior: str
    input_sequence: list[dict[str, Any]] = field(default_factory=list)  # the attack sent this step
    error: str | None = None

    def to_record(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvalResult:
    case_id: str
    category: str
    result: str  # pass | fail | partial | error
    expected_result: str
    surprise: bool
    requires_judge: bool
    authority: str  # detector | judge_pending
    steps: list[StepOutcome]
    cost: dict[str, Any]
    executed_at: str
    target_system_version: str = "unknown"
    verdict: dict[str, Any] | None = None  # the Judge's Verdict when authority='judge'
    schema_version: str = _RESULT_SCHEMA_VERSION

    def to_record(self) -> dict[str, Any]:
        record = asdict(self)
        record["steps"] = [s.to_record() for s in self.steps]
        if self.verdict is None:
            record.pop("verdict", None)  # keep the record clean when no Judge ran
        return record


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _transcript_text(target_result: Any) -> str:
    """Concatenate the target's assistant turns into one detector haystack."""
    return "\n".join(t.content for t in target_result.target_transcript)


def _is_surprise(result: str, authority: str, expected_result: str) -> bool:
    """Whether a result contradicts its authoring-time expectation, meaningfully.

    A "surprise" is the signal the Orchestrator and regression harness care about
    most — a defense expected to hold that broke, or a confirmed finding that
    stopped reproducing. It only counts when the result is authoritative — a
    deterministic detector ('detector') or the Judge ('judge'). A run error, or a
    'judge_pending' case whose coarse detector is not the final word, is never a
    surprise.
    """
    return result != "error" and authority in ("detector", "judge") and result != expected_result


def _roll_up(step_results: list[StepResult]) -> str:
    """Case verdict = the worst step verdict (setup steps don't count)."""
    graded = [r for r in step_results if r != "setup"]
    if not graded:
        return "error"
    worst = max(graded, key=lambda r: _SEVERITY_ORDER[r])
    return worst


def fetch_target_version(base_url: str | None = None, *, client: httpx.Client | None = None) -> str:
    """Best-effort read of the deployed target's version from /health.

    Never raises — a version tag is metadata for the run log, not a gate. On any
    failure it returns 'unknown' so a version-endpoint change can't break a run.
    """
    owns = client is None
    http = client or httpx.Client(base_url=base_url or TARGET_BASE_URL, timeout=TARGET_TIMEOUT_S)
    try:
        resp = http.get("/health")
        if resp.status_code < 400:
            data = resp.json()
            return str(data.get("version") or data.get("target_system_version") or "unknown")
    except (httpx.HTTPError, ValueError, KeyError):
        return "unknown"
    finally:
        if owns:
            http.close()
    return "unknown"


def run_case(
    case: EvalCase,
    *,
    base_url: str | None = None,
    client: httpx.Client | None = None,
    target_version: str = "unknown",
    judge: JudgeFn | None = None,
    judge_all: bool = False,
) -> EvalResult:
    """Execute one case's steps live and produce an EvalResult.

    Steps run in order. A step whose `session` is 'reuse:<step_id>' continues
    the target conversation opened by that earlier step (this is what lets a
    later step probe whether an earlier patient's memory bled across). A
    TargetError on any step is captured as an 'error' step (and short-circuits
    the case) rather than crashing the whole suite.

    If a `judge` is supplied, the Phase 4 Judge produces the authoritative
    verdict for cases marked `requires_judge` (or every case when `judge_all`),
    replacing the coarse detector result. Cases the Judge doesn't score keep
    their deterministic detector result exactly as before.
    """
    owns_client = client is None
    http = client or httpx.Client(base_url=base_url or TARGET_BASE_URL, timeout=TARGET_TIMEOUT_S)

    step_outcomes: list[StepOutcome] = []
    session_ids: dict[str, str] = {}  # step_id -> target conversation_id
    judge_input_turns: list[dict[str, Any]] = []  # attacker turns across all steps
    judge_transcript_turns: list[dict[str, Any]] = []  # target turns across all steps
    total_tokens = 0
    total_usd = 0.0

    try:
        for step in case.steps:
            session_id = session_ids.get(step.reuse_of) if step.reuse_of else None
            try:
                target_result = send_to_target(
                    session_id=session_id,
                    messages=list(step.input_sequence),
                    patient_id=step.patient_id,
                    client=http,
                )
            except TargetError as exc:
                step_outcomes.append(
                    StepOutcome(
                        step_id=step.step_id,
                        patient_id=step.patient_id,
                        session_id=session_id,
                        result="error",
                        detector_matched=None,
                        observed_behavior="",
                        input_sequence=[dict(m) for m in step.input_sequence],
                        error=str(exc),
                    )
                )
                break  # can't reliably continue a threaded session past a failed step

            session_ids[step.step_id] = target_result.session_id
            total_tokens += int(target_result.cost.get("tokens", 0))
            total_usd += float(target_result.cost.get("usd", 0.0))
            judge_input_turns.extend(dict(m) for m in step.input_sequence)
            judge_transcript_turns.extend(target_result.transcript_as_dicts())

            transcript = _transcript_text(target_result)
            step_outcomes.append(_grade_step(step, target_result, transcript))
    finally:
        if owns_client:
            http.close()

    result = _roll_up([o.result for o in step_outcomes])
    requires_judge = case.requires_judge
    authority = "judge_pending" if requires_judge else "detector"
    verdict_record: dict[str, Any] | None = None

    should_judge = judge is not None and result != "error" and (requires_judge or judge_all)
    if should_judge:
        verdict = judge(
            JudgeInput(
                attack_category=case.category,
                invariant=case.invariant,
                expected_safe_behavior=case.expected_safe_behavior,
                input_sequence=judge_input_turns,
                target_transcript=judge_transcript_turns,
            )
        )
        result = verdict.result
        authority = "judge"
        verdict_record = verdict.verdict
        total_tokens += int(verdict.cost.get("tokens", 0))
        total_usd += float(verdict.cost.get("usd", 0.0))

    surprise = _is_surprise(result, authority, case.expected_result)

    return EvalResult(
        case_id=case.case_id,
        category=case.category,
        result=result,
        expected_result=case.expected_result,
        surprise=surprise,
        requires_judge=requires_judge,
        authority=authority,
        steps=step_outcomes,
        cost={"tokens": total_tokens, "usd": round(total_usd, 6)},
        executed_at=_now_iso(),
        target_system_version=target_version,
        verdict=verdict_record,
    )


def _grade_step(step: Step, target_result: Any, transcript: str) -> StepOutcome:
    snippet = transcript[:_TRANSCRIPT_SNIPPET_CHARS]
    attack = [dict(m) for m in step.input_sequence]
    if step.detector is None:
        return StepOutcome(
            step_id=step.step_id,
            patient_id=step.patient_id,
            session_id=target_result.session_id,
            result="setup",
            detector_matched=None,
            observed_behavior=snippet,
            input_sequence=attack,
        )
    matched = step.detector.matched(transcript)
    return StepOutcome(
        step_id=step.step_id,
        patient_id=step.patient_id,
        session_id=target_result.session_id,
        result=step.detector.outcome(transcript),
        detector_matched=matched,
        observed_behavior=snippet,
        input_sequence=attack,
    )


def run_suite(
    cases: list[EvalCase],
    *,
    base_url: str | None = None,
    fetch_version: bool = True,
    judge: JudgeFn | None = None,
    judge_all: bool = False,
) -> list[EvalResult]:
    """Run every case live over a shared connection pool; return all results.

    Pass `judge` to have the Phase 4 Judge finalize `requires_judge` cases (or
    every case with `judge_all`); omit it for the deterministic-only Phase 3 run.
    """
    with httpx.Client(base_url=base_url or TARGET_BASE_URL, timeout=TARGET_TIMEOUT_S) as http:
        version = fetch_target_version(client=http) if fetch_version else "unknown"
        return [
            run_case(c, client=http, target_version=version, judge=judge, judge_all=judge_all)
            for c in cases
        ]


def write_results_jsonl(results: list[EvalResult], out_path: str | Path) -> Path:
    """Append one JSON object per result to a JSONL run log (created if absent)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r.to_record(), ensure_ascii=False) + "\n")
    return out_path
