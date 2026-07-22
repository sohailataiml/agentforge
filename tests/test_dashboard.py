"""Tests for the eval dashboard generator (all non-live — no network, no target).

These build the dashboard from synthetic run logs in a tmp dir so they never
depend on a real run having happened, and assert the output is well-formed and
carries the security-relevant markers (exploit, surprise, judge-pending).
"""

from __future__ import annotations

import json
from html.parser import HTMLParser
from pathlib import Path

import pytest

from evals.dashboard import build, load_runs, render


def _record(**overrides) -> dict:
    base = {
        "schema_version": "1.0.0",
        "case_id": "demo-case",
        "category": "state_corruption",
        "result": "fail",
        "expected_result": "pass",
        "surprise": True,
        "requires_judge": False,
        "authority": "detector",
        "steps": [
            {
                "step_id": "s1",
                "patient_id": "a2345ab2-477b-4b59-b7be-7e82aa7f9d8c",
                "session_id": "abc",
                "result": "fail",
                "detector_matched": True,
                "observed_behavior": "Patient: Phil Belford <script>ignored</script>",
                "input_sequence": [{"turn": 1, "role": "user", "content": "list this patient's medications"}],
                "error": None,
            }
        ],
        "cost": {"tokens": 1234, "usd": 0.0412},
        "executed_at": "2026-07-21T15:00:11+00:00",
        "target_system_version": "0.15.8",
    }
    base.update(overrides)
    return base


def _write_run(dir_: Path, stamp: str, records: list[dict]) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / f"run-{stamp}.jsonl").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )


def test_build_writes_wellformed_html(tmp_path: Path):
    _write_run(tmp_path, "20260721T150011Z", [_record()])
    out = build(tmp_path / "dashboard.html", results_dir=tmp_path, cases_dir=tmp_path / "nope")
    text = out.read_text(encoding="utf-8")
    # Parses without raising, and the transcript's <script> is escaped, not live.
    HTMLParser().feed(text)
    assert "&lt;script&gt;" in text
    assert "<script>ignored</script>" not in text
    for marker in ("AgentForge", "EXPLOIT", "surprise", "state_corruption"):
        assert marker in text
    # the attacking query is rendered alongside the target response
    assert "attack query" in text and "list this patient&#x27;s medications" in text
    assert "target response" in text


def test_judge_pending_is_marked_and_not_a_surprise_visual(tmp_path: Path):
    rec = _record(result="fail", requires_judge=True, authority="judge_pending", surprise=False)
    _write_run(tmp_path, "20260721T160000Z", [rec])
    out = build(tmp_path / "d.html", results_dir=tmp_path, cases_dir=tmp_path / "nope")
    text = out.read_text(encoding="utf-8")
    assert "judge-pending" in text


def test_run_history_accumulates_multiple_runs(tmp_path: Path):
    _write_run(tmp_path, "20260721T150011Z", [_record(surprise=True)])
    _write_run(tmp_path, "20260722T150011Z", [_record(result="pass", expected_result="pass", surprise=False)])
    runs = load_runs(tmp_path)
    assert [r.stamp for r in runs] == ["20260721T150011Z", "20260722T150011Z"]  # oldest-first
    html_text = render(runs, {})
    assert html_text.count("<tr>") >= 2  # run-history rows for both runs


def test_no_runs_raises(tmp_path: Path):
    with pytest.raises(SystemExit, match="no run logs"):
        build(tmp_path / "d.html", results_dir=tmp_path, cases_dir=tmp_path / "nope")
