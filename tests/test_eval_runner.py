"""Tests for the eval runner.

The non-live tests cover the deterministic roll-up and the error path (both run
without touching the network — the error path is triggered by input validation
that happens before any HTTP call). The `live` tests execute a real seed case
against the deployed target, per the platform's no-mocks constraint.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from agentforge.eval_case import EvalCase, load_case
from agentforge.eval_runner import _is_surprise, _roll_up, run_case

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CASES_DIR = _REPO_ROOT / "evals" / "cases"
_RESULT_SCHEMA = _REPO_ROOT / "contracts" / "eval_result.schema.json"


def test_roll_up_picks_worst_step_verdict():
    assert _roll_up(["pass", "fail", "pass"]) == "fail"
    assert _roll_up(["pass", "partial"]) == "partial"
    assert _roll_up(["setup", "pass"]) == "pass"
    assert _roll_up(["error", "fail"]) == "error"
    assert _roll_up(["setup"]) == "error"  # nothing gradable


def test_surprise_only_fires_for_authoritative_detector():
    # Detector authoritative + result contradicts expectation -> surprise.
    assert _is_surprise("fail", "detector", "pass") is True
    assert _is_surprise("pass", "detector", "fail") is True
    # Matches expectation -> not a surprise.
    assert _is_surprise("fail", "detector", "fail") is False
    # judge_pending is never authoritative, so it never surprises...
    assert _is_surprise("fail", "judge_pending", "pass") is False
    # ...and an infra error is never a security surprise.
    assert _is_surprise("error", "detector", "pass") is False


def _minimal_case(input_sequence: list[dict]) -> EvalCase:
    return EvalCase.from_dict(
        {
            "schema_version": "1.0.0",
            "case_id": "tmp",
            "category": "identity_role",
            "subcategory": "x",
            "owasp_refs": ["LLM01"],
            "description": "x",
            "test_type": "invariant",
            "invariant": "x",
            "expected_safe_behavior": "x",
            "severity": "low",
            "exploitability": "low",
            "add_to_regression": False,
            "expected_result": "pass",
            "steps": [
                {
                    "step_id": "s1",
                    "patient_id": "p1",
                    "session": "new",
                    "input_sequence": input_sequence,
                }
            ],
        }
    )


def test_run_case_captures_target_error_as_error_step_without_network():
    # A system_context-only sequence has no 'user' turn, so send_to_target
    # raises before any HTTP call. run_case must record it as an error step,
    # not crash — and an error is never a "surprise".
    case = _minimal_case([{"turn": 1, "role": "system_context", "content": "x"}])
    result = run_case(case)
    assert result.result == "error"
    assert result.surprise is False
    assert result.steps[0].result == "error"
    assert result.steps[0].error and "user" in result.steps[0].error
    # the attack that was attempted is captured on the step for the results view
    assert result.steps[0].input_sequence == [{"turn": 1, "role": "system_context", "content": "x"}]


def test_runner_output_conforms_to_eval_result_contract():
    # Both sides of the seam must agree: a record the runner emits must validate
    # against contracts/eval_result.schema.json. Uses the no-network error path.
    case = _minimal_case([{"turn": 1, "role": "system_context", "content": "x"}])
    record = run_case(case).to_record()
    schema = json.loads(_RESULT_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(record), key=lambda e: e.path)
    assert not errors, [e.message for e in errors]


@pytest.mark.live
def test_live_run_single_case_produces_gradeable_result():
    case = load_case(_CASES_DIR / "data_exfiltration" / "unauthenticated-phi-retrieval.yaml")
    result = run_case(case)
    assert result.result in {"pass", "fail", "partial"}
    assert result.cost["tokens"] > 0
    assert result.steps[0].observed_behavior
    # This is the confirmed-live auth-bypass finding; expect the exploit to land.
    assert result.result == "fail"
    assert result.surprise is False  # expected_result is 'fail', so no surprise
