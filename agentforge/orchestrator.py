"""Orchestrator (Phase 6) — the strategy layer that drives the autonomous loop.

Deterministic (no LLM). It reads observability state (what's been attacked, what's
open, what regressed, what's been spent), scores the attack categories, and emits
`AttackDirective`s (contracts/attack_directive.schema.json) for the Red Team —
enforcing a spend budget, a per-category **kill-switch** for low-signal campaigns,
a **regression trigger** on target-version change, and **backoff → queue → abort**
handling when an external API rate-limits us.

The scoring, directive emission, and loop control are pure and injectable, so the
whole strategy is unit-tested without the network. `read_observation` assembles
state from the run logs, the regression DB, and the report corpus; the CLI wires a
live executor (Red Team + Judge) and the Regression Harness.
"""

from __future__ import annotations

import argparse
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from agentforge.rubrics import CATEGORIES

_ROOT = Path(__file__).resolve().parent.parent
_DIRECTIVE_SCHEMA = _ROOT / "contracts" / "attack_directive.schema.json"
_RESULTS_DIR = _ROOT / "evals" / "results"
_REPORTS_DIR = _ROOT / "reports"

# OWASP references per category, so an emitted directive is always contract-valid.
_OWASP = {
    "prompt_injection": ["LLM01"],
    "data_exfiltration": ["LLM02", "A01"],
    "state_corruption": ["LLM01", "A01"],
    "tool_misuse": ["LLM07", "A04"],
    "dos": ["LLM04"],
    "identity_role": ["LLM01", "A01"],
}

# Scoring weights (higher score => attack this category next). Tuned so the
# priority order is regression >> open high-sev > coverage gap: a broken defense is
# always the most urgent thing, a known-weak category outranks exploring a fresh
# one, and an unexplored category still gets attention.
_W_COVERAGE = 1.0     # reward under-explored categories (max = _W_COVERAGE*_MIN_ATTEMPTS = 3)
_W_HIGHSEV = 4.0      # keep probing where the target is already weak
_W_REGRESSION = 10.0  # a reappeared/broken defense is the most urgent signal
_MIN_ATTEMPTS = 3     # "explored enough" threshold for the coverage term

# Kill-switch: after this much spend with signal yield below this, stop the category.
_KILL_MIN_SPEND_USD = 0.50
_KILL_MIN_YIELD = 0.5           # exploits per USD
_DEFAULT_TOKEN_BUDGET = 2000
_DEFAULT_MAX_TURNS = 3


class OrchestratorError(RuntimeError):
    """The loop hit an unrecoverable condition (e.g. sustained rate limiting)."""


class RateLimited(RuntimeError):
    """An executor signals the external API rate-limited this directive."""


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #

@dataclass
class CategoryState:
    category: str
    attempts: int = 0
    exploits: int = 0          # confirmed exploits found here
    high_sev_open: int = 0     # open critical/high findings
    regressions: int = 0       # regression/reappearance alerts this cycle
    spend_usd: float = 0.0
    killed: bool = False

    @property
    def signal_yield(self) -> float:
        return self.exploits / self.spend_usd if self.spend_usd > 0 else 0.0


@dataclass
class Observation:
    categories: dict[str, CategoryState]
    target_version: str = "unknown"
    last_seen_version: str | None = None
    total_spend_usd: float = 0.0
    budget_usd: float = 5.0

    @staticmethod
    def empty(budget_usd: float = 5.0) -> Observation:
        return Observation({c: CategoryState(c) for c in CATEGORIES}, budget_usd=budget_usd)


# --------------------------------------------------------------------------- #
# scoring + kill-switch
# --------------------------------------------------------------------------- #

@dataclass
class CategoryScore:
    category: str
    score: float
    reasons: dict[str, float]


def score_categories(obs: Observation) -> list[CategoryScore]:
    """Rank categories by attack priority. Pure function of the observation."""
    scores = []
    for cat, st in obs.categories.items():
        if st.killed:
            continue
        coverage = _W_COVERAGE * max(0, _MIN_ATTEMPTS - st.attempts)
        highsev = _W_HIGHSEV * st.high_sev_open
        regression = _W_REGRESSION * st.regressions
        total = coverage + highsev + regression
        scores.append(CategoryScore(cat, total, {
            "coverage": coverage, "high_sev": highsev, "regression": regression,
        }))
    scores.sort(key=lambda s: s.score, reverse=True)
    return scores


def apply_kill_switch(obs: Observation) -> list[str]:
    """Trip the kill-switch on categories that have spent enough with too little
    signal and nothing urgent open. Returns the newly-killed categories."""
    killed = []
    for st in obs.categories.values():
        if st.killed:
            continue
        if (st.spend_usd >= _KILL_MIN_SPEND_USD and st.signal_yield < _KILL_MIN_YIELD
                and st.high_sev_open == 0 and st.regressions == 0):
            st.killed = True
            killed.append(st.category)
    return killed


def should_run_regression(obs: Observation) -> bool:
    """Replay the corpus when the target changed under us."""
    return obs.last_seen_version is not None and obs.target_version != obs.last_seen_version


# --------------------------------------------------------------------------- #
# directive emission
# --------------------------------------------------------------------------- #

def _priority(st: CategoryState) -> str:
    if st.regressions > 0:
        return "critical"
    if st.high_sev_open > 0:
        return "high"
    return "medium"


def next_directive(obs: Observation) -> dict[str, Any] | None:
    """Emit the highest-priority AttackDirective, or None if the budget is spent or
    nothing is worth attacking. The returned directive is schema-validated."""
    if obs.total_spend_usd >= obs.budget_usd:
        return None
    apply_kill_switch(obs)
    ranked = [s for s in score_categories(obs) if s.score > 0]
    if not ranked:
        return None
    top = ranked[0]
    st = obs.categories[top.category]
    directive = {
        "schema_version": "1.0.0",
        "directive_id": str(uuid.uuid4()),
        "attack_category": top.category,
        "subcategory": f"autonomous {top.category} probe (coverage/high-sev/regression driven)",
        "owasp_refs": _OWASP[top.category],
        "strategy_hint": "novel",
        "token_budget": _DEFAULT_TOKEN_BUDGET,
        "max_turns": _DEFAULT_MAX_TURNS,
        "priority": _priority(st),
        "issued_at": datetime.now(timezone.utc).isoformat(),
    }
    _validate_directive(directive)
    return directive


def _validate_directive(directive: dict[str, Any]) -> None:
    schema = json.loads(_DIRECTIVE_SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(directive), key=lambda e: e.path)
    if errors:
        raise OrchestratorError(f"emitted directive failed schema validation: {errors[0].message}")


# --------------------------------------------------------------------------- #
# the loop
# --------------------------------------------------------------------------- #

@dataclass
class ExecutionOutcome:
    exploits: int
    spend_usd: float
    detail: str = ""
    attempts: list[dict[str, Any]] = field(default_factory=list)  # per-attempt attack/transcript/verdict


@dataclass
class OrchestrationReport:
    started_at: str
    finished_at: str = ""
    directives: list[dict[str, Any]] = field(default_factory=list)
    results: list[dict[str, Any]] = field(default_factory=list)  # directive paired with its live Red Team result
    queued: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[str] = field(default_factory=list)
    exploits: int = 0
    spend_usd: float = 0.0
    regression: dict[str, Any] | None = None
    aborted: bool = False


def orchestrate(
    obs: Observation,
    *,
    executor: Callable[[dict[str, Any]], ExecutionOutcome],
    regression_runner: Callable[[], dict[str, Any]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    max_directives: int = 10,
    max_rate_limit_streak: int = 3,
    backoff_base_s: float = 1.0,
) -> OrchestrationReport:
    """Drive the autonomous loop: (optionally) regress on target change, then issue
    directives to `executor` until the budget is spent, nothing scores, or the API
    rate-limits us past the abort threshold.

    Rate-limit handling is **backoff → queue → abort**: each RateLimited backs off
    exponentially and defers (queues) the directive; a sustained streak aborts.
    Outcomes feed back into `obs`, so scores shift as categories are exhausted.
    """
    report = OrchestrationReport(started_at=datetime.now(timezone.utc).isoformat())

    if regression_runner is not None and should_run_regression(obs):
        report.regression = regression_runner()
        report.decisions.append(f"target changed {obs.last_seen_version} -> {obs.target_version}: ran regression")

    rate_limit_streak = 0
    while len(report.directives) < max_directives:
        if obs.total_spend_usd >= obs.budget_usd:
            report.decisions.append(f"budget ${obs.budget_usd:.2f} exhausted -> stop")
            break
        directive = next_directive(obs)
        if directive is None:
            report.decisions.append("no category worth attacking (killed/covered) -> stop")
            break

        category = directive["attack_category"]
        try:
            outcome = executor(directive)
        except RateLimited:
            rate_limit_streak += 1
            if rate_limit_streak >= max_rate_limit_streak:
                report.decisions.append(f"rate-limited x{rate_limit_streak} -> abort")
                report.aborted = True
                break
            sleep(backoff_base_s * (2 ** (rate_limit_streak - 1)))   # exponential backoff
            report.queued.append(directive)                          # queue/defer
            report.decisions.append(f"rate-limited on {category} -> backoff+queue (streak {rate_limit_streak})")
            continue

        rate_limit_streak = 0
        st = obs.categories[category]
        st.attempts += 1
        st.exploits += outcome.exploits
        st.spend_usd += outcome.spend_usd
        obs.total_spend_usd += outcome.spend_usd
        report.directives.append(directive)
        report.results.append({
            "directive": directive, "exploits": outcome.exploits,
            "spend_usd": outcome.spend_usd, "attempts": outcome.attempts,
        })
        report.exploits += outcome.exploits
        report.spend_usd += outcome.spend_usd
        killed = apply_kill_switch(obs)
        if killed:
            report.decisions.append(f"kill-switch: {', '.join(killed)} (low signal yield)")

    report.finished_at = datetime.now(timezone.utc).isoformat()
    return report


# --------------------------------------------------------------------------- #
# observability: read state from the filesystem (best-effort)
# --------------------------------------------------------------------------- #

def read_observation(*, budget_usd: float = 5.0) -> Observation:
    """Assemble an Observation from the run logs, the report corpus, and the
    regression DB. Best-effort: missing sources just leave zeros."""
    obs = Observation.empty(budget_usd=budget_usd)

    # Run logs give the coverage signal (attempts per category). Spend/exploits are
    # left at zero: the budget and kill-switch govern the *fresh* campaign about to
    # run, not the cumulative history — otherwise historical spend would trip the
    # budget before a single directive is issued.
    for log in sorted(_RESULTS_DIR.glob("run-*.jsonl")):
        for line in log.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            st = obs.categories.get(rec.get("category"))
            if st is not None:
                st.attempts += 1

    if _REPORTS_DIR.exists():
        for jf in _REPORTS_DIR.glob("AF-*.json"):
            try:
                r = json.loads(jf.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            st = obs.categories.get(r.get("attack_category"))
            if st and r.get("status") not in ("resolved", "wont_fix") and r.get("severity") in ("critical", "high"):
                st.high_sev_open += 1

    _read_regression_state(obs)
    return obs


def _read_regression_state(obs: Observation) -> None:
    import sqlite3

    db = _RESULTS_DIR / "regression.db"
    if not db.exists():
        return
    try:
        conn = sqlite3.connect(str(db))
        conn.row_factory = sqlite3.Row
        runs = conn.execute("SELECT run_id, target_version FROM runs ORDER BY started_at DESC LIMIT 2").fetchall()
        if runs:
            obs.target_version = runs[0]["target_version"]
            obs.last_seen_version = runs[1]["target_version"] if len(runs) > 1 else None
            for row in conn.execute(
                "SELECT e.category AS category, COUNT(*) AS n FROM run_results r "
                "JOIN exploits e ON e.case_id = r.case_id "
                "WHERE r.run_id = ? AND (r.status = 'regressed' OR r.reappeared = 1) GROUP BY e.category",
                (runs[0]["run_id"],),
            ):
                st = obs.categories.get(row["category"])
                if st:
                    st.regressions += int(row["n"])
        conn.close()
    except sqlite3.Error:
        return


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def _live_executor(patient_id: str) -> Callable[[dict[str, Any]], ExecutionOutcome]:
    from agentforge.judge import judge_attempt
    from agentforge.red_team import build_directive, run_directive
    from agentforge.red_team_client import RedTeamError

    def _run(directive: dict[str, Any]) -> ExecutionOutcome:
        d = build_directive(
            directive["attack_category"], directive["subcategory"], directive["owasp_refs"],
            strategy_hint=directive.get("strategy_hint", "novel"),
            token_budget=directive["token_budget"], max_turns=directive["max_turns"],
        )
        try:
            campaign = run_directive(d, patient_id, judge=judge_attempt, variants_on_partial=1)
        except RedTeamError as exc:
            if "429" in str(exc) or "rate" in str(exc).lower():
                raise RateLimited(str(exc)) from exc
            raise
        exploits = sum(1 for r in campaign.records if r.verdict and r.verdict["result"] == "fail")
        attempts = [
            {
                "attack": r.attempt["input_sequence"], "transcript": r.attempt["target_transcript"],
                "verdict": r.verdict, "model": r.served_model, "fell_back": r.fell_back,
            }
            for r in campaign.records if r.attempt is not None
        ]
        return ExecutionOutcome(exploits=exploits, spend_usd=campaign.total_cost.get("usd", 0.0), attempts=attempts)

    return _run


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agentforge.orchestrator", description="Autonomous attack orchestrator")
    p.add_argument("--budget", type=float, default=2.0, help="total spend budget in USD")
    p.add_argument("--max-directives", type=int, default=6)
    p.add_argument("--patient-id", default="a2345ab2-477b-4b59-b7be-7e82aa7f9d8c")
    p.add_argument("--dry-run", action="store_true", help="score + emit directives only; no execution")
    args = p.parse_args(argv)

    obs = read_observation(budget_usd=args.budget)
    print("category scores:")
    for s in score_categories(obs):
        print(f"  {s.category:<18} {s.score:6.1f}  {s.reasons}")

    if args.dry_run:
        d = next_directive(obs)
        print("\nnext directive:", json.dumps(d, indent=2) if d else "(none)")
        return 0

    from agentforge.regression import connect, register_from_cases, run_regression, to_campaign_result
    from agentforge.eval_case import load_all_cases

    def _regress() -> dict[str, Any]:
        conn = connect()
        register_from_cases(conn, load_all_cases(_ROOT / "evals" / "cases"))
        summary = run_regression(conn)
        conn.close()
        return to_campaign_result(summary)

    report = orchestrate(obs, executor=_live_executor(args.patient_id), regression_runner=_regress,
                         max_directives=args.max_directives)
    print(f"\nissued {len(report.directives)} directive(s), {report.exploits} exploit(s), "
          f"${report.spend_usd:.4f} spent, {len(report.queued)} queued"
          + (" [ABORTED]" if report.aborted else ""))
    for d in report.decisions:
        print(f"  - {d}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
