"""Tests for the Orchestrator (Phase 6).

The strategy core is pure and deterministic: category scoring, the kill-switch,
schema-valid directive emission, the regression trigger on target change, and the
budget / backoff→queue→abort loop control — all driven with a stub executor, no
network.
"""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from agentforge.orchestrator import (
    ExecutionOutcome,
    Observation,
    RateLimited,
    apply_kill_switch,
    next_directive,
    orchestrate,
    score_categories,
    should_run_regression,
)

_DIRECTIVE_SCHEMA = json.loads(
    (Path(__file__).resolve().parent.parent / "contracts" / "attack_directive.schema.json").read_text(encoding="utf-8")
)


def _obs(budget: float = 5.0) -> Observation:
    return Observation.empty(budget_usd=budget)


# --------------------------------------------------------------------------- #
# scoring + kill-switch
# --------------------------------------------------------------------------- #

def test_regression_outranks_highsev_outranks_coverage():
    obs = _obs()
    obs.categories["prompt_injection"].attempts = 10          # fully covered -> coverage 0
    obs.categories["prompt_injection"].regressions = 1        # but a regression -> top
    obs.categories["data_exfiltration"].attempts = 10
    obs.categories["data_exfiltration"].high_sev_open = 1     # weak spot -> second
    ranked = score_categories(obs)
    assert ranked[0].category == "prompt_injection"
    assert ranked[1].category == "data_exfiltration"
    assert ranked[0].score > ranked[1].score


def test_killed_category_is_excluded_from_scoring():
    obs = _obs()
    obs.categories["dos"].killed = True
    assert all(s.category != "dos" for s in score_categories(obs))


def test_kill_switch_trips_on_low_signal_but_spares_urgent():
    obs = _obs()
    lo = obs.categories["dos"]
    lo.spend_usd, lo.exploits = 1.0, 0                        # spent, no signal -> kill
    weak = obs.categories["tool_misuse"]
    weak.spend_usd, weak.exploits, weak.high_sev_open = 1.0, 0, 1   # spent, no yield, but open high-sev -> spared
    killed = apply_kill_switch(obs)
    assert "dos" in killed and "tool_misuse" not in killed
    assert obs.categories["dos"].killed and not obs.categories["tool_misuse"].killed


# --------------------------------------------------------------------------- #
# directive emission
# --------------------------------------------------------------------------- #

def test_emitted_directive_is_schema_valid_and_prioritized():
    obs = _obs()
    obs.categories["data_exfiltration"].regressions = 1       # -> critical priority
    d = next_directive(obs)
    assert not [e.message for e in Draft202012Validator(_DIRECTIVE_SCHEMA).iter_errors(d)]
    assert d["attack_category"] == "data_exfiltration" and d["priority"] == "critical"


def test_no_directive_when_budget_exhausted():
    obs = _obs(budget=1.0)
    obs.total_spend_usd = 1.0
    assert next_directive(obs) is None


def test_should_run_regression_only_on_version_change():
    obs = _obs()
    obs.target_version, obs.last_seen_version = "0.16.0", "0.15.8"
    assert should_run_regression(obs) is True
    obs.last_seen_version = "0.16.0"
    assert should_run_regression(obs) is False
    obs.last_seen_version = None                              # never seen before -> don't regress
    assert should_run_regression(obs) is False


# --------------------------------------------------------------------------- #
# loop
# --------------------------------------------------------------------------- #

def test_loop_stops_at_budget_and_feeds_outcomes_back():
    obs = _obs(budget=1.0)
    # each directive "costs" $0.30 and finds 1 exploit
    report = orchestrate(obs, executor=lambda d: ExecutionOutcome(exploits=1, spend_usd=0.30), max_directives=100)
    assert report.spend_usd >= 1.0 and report.exploits == len(report.directives)
    assert any("budget" in dec for dec in report.decisions)


def test_loop_triggers_regression_on_target_change():
    obs = _obs()
    obs.target_version, obs.last_seen_version = "0.16.0", "0.15.8"
    ran = {"n": 0}

    def regress():
        ran["n"] += 1
        return {"regressions_detected": 0}

    orchestrate(obs, executor=lambda d: ExecutionOutcome(0, 0.10), regression_runner=regress, max_directives=1)
    assert ran["n"] == 1


def test_rate_limit_backs_off_queues_then_aborts():
    obs = _obs()
    slept = []

    def always_limited(d):
        raise RateLimited("429 too many requests")

    report = orchestrate(obs, executor=always_limited, sleep=slept.append,
                         max_rate_limit_streak=3, backoff_base_s=0.5)
    assert report.aborted and any("abort" in d for d in report.decisions)
    assert len(report.queued) == 2                            # queued twice before the 3rd aborts
    assert slept == [0.5, 1.0]                                # exponential backoff between retries
