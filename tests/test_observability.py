"""Tests for the observability queries (Phase 8).

Each query is asserted against synthetic run logs, a report corpus, and regression
runs written to a tmp dir — so the six operational questions have deterministic,
checkable answers.
"""

from __future__ import annotations

import json

from agentforge.observability import (
    agent_timeline,
    cases_per_category,
    cost_summary,
    pass_fail_by_category_version,
    resilience_trend,
    vuln_status,
)

_RECORDS = [
    {"case_id": "c1", "category": "data_exfiltration", "result": "fail", "target_system_version": "0.15.8",
     "executed_at": "2026-07-20T10:00:00+00:00", "cost": {"usd": 0.05, "tokens": 1000},
     "verdict": {"result": "fail", "severity": "critical", "judged_at": "2026-07-20T10:00:05+00:00"}},
    {"case_id": "c2", "category": "data_exfiltration", "result": "pass", "target_system_version": "0.15.8",
     "executed_at": "2026-07-20T10:01:00+00:00", "cost": {"usd": 0.03, "tokens": 600}},
    {"case_id": "c3", "category": "prompt_injection", "result": "pass", "target_system_version": "0.15.8",
     "executed_at": "2026-07-20T10:02:00+00:00", "cost": {"usd": 0.02, "tokens": 400}},
    {"case_id": "c4", "category": "prompt_injection", "result": "error", "target_system_version": "0.15.8",
     "executed_at": "2026-07-20T10:03:00+00:00", "cost": {"usd": 0.0, "tokens": 0}},
]
_REPORTS = [
    {"vuln_id": "AF-2026-0001", "severity": "critical", "status": "open", "attack_category": "data_exfiltration",
     "created_at": "2026-07-21T09:00:00+00:00"},
    {"vuln_id": "AF-2026-0002", "severity": "high", "status": "resolved", "attack_category": "state_corruption",
     "created_at": "2026-07-21T09:05:00+00:00"},
]
_RUNS = [
    {"target_version": "0.15.8", "started_at": "2026-07-20T12:00:00+00:00", "checked": 5, "reproduces": 3, "regressed": 0, "fixed": 0},
    {"target_version": "0.16.0", "started_at": "2026-07-22T12:00:00+00:00", "checked": 5, "reproduces": 1, "regressed": 1, "fixed": 2},
]


def test_cases_per_category():
    assert cases_per_category(_RECORDS) == {"data_exfiltration": 2, "prompt_injection": 2}


def test_pass_fail_by_category_version():
    out = pass_fail_by_category_version(_RECORDS)
    de = out["data_exfiltration @ 0.15.8"]
    assert de["pass"] == 1 and de["fail"] == 1 and de["resilience_rate"] == 0.5
    pi = out["prompt_injection @ 0.15.8"]
    assert pi["error"] == 1 and pi["resilience_rate"] == 1.0  # error excluded from the rate


def test_resilience_trend_improves_over_versions():
    trend = resilience_trend(_RUNS)
    assert trend[0]["resilience"] == 0.4 and trend[1]["resilience"] == 0.8  # 3/5 -> 1/5 reproduce
    assert trend[1]["regressed"] == 1


def test_vuln_status_counts():
    vs = vuln_status(_REPORTS)
    assert vs["by_status"]["open"] == 1 and vs["by_status"]["resolved"] == 1
    assert vs["open_high_or_critical"] == 1  # the open critical; the resolved high doesn't count
    assert vs["total"] == 2


def test_cost_summary_and_scaling():
    cs = cost_summary(_RECORDS)
    assert cs["cases"] == 4 and cs["total_usd"] == 0.1
    assert cs["per_case_usd"] == 0.025 and cs["projected_usd_per_1k"] == 25.0


def test_agent_timeline_is_chronological_and_multi_agent():
    tl = agent_timeline(_RECORDS, _REPORTS, _RUNS)
    agents = {e["agent"] for e in tl}
    assert {"Eval Runner", "Judge", "Documentation", "Regression"} <= agents
    ts = [e["ts"] for e in tl]
    assert ts == sorted(ts)  # sorted ascending


def test_loaders_read_from_disk(tmp_path):
    from agentforge.observability import load_records, load_reports

    (tmp_path / "run-20260720T100000Z.jsonl").write_text(
        "\n".join(json.dumps(r) for r in _RECORDS), encoding="utf-8")
    (tmp_path / "AF-2026-0001.json").write_text(json.dumps(_REPORTS[0]), encoding="utf-8")
    assert len(load_records(tmp_path)) == 4
    assert load_reports(tmp_path)[0]["vuln_id"] == "AF-2026-0001"
