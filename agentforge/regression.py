"""Regression Harness (Phase 6) — deterministic replay of confirmed exploits.

**No LLM.** It replays the exact stored attack sequences against the live target
and asserts the *violated invariant* via each case's deterministic detector — not
string equality — so a fix that avoids the old string but still leaks is still a
fail. It persists a versioned exploit corpus + run history in SQLite and flags:

  - **regressed**: a defense that used to hold now breaks (or a confirmed exploit
    got worse) — the alert the Orchestrator cares about most;
  - **reappeared**: an exploit that was fixed reproduces again (tracked across runs);
  - **fixed**: an exploit that no longer reproduces (update the corpus);
  - **reproduces / stable**: unchanged vs the frozen baseline.

Because replay is deterministic (detectors, not a Judge) and the target is
unauthenticated, a regression run needs no API credits. Runs on demand, or when
the Orchestrator detects a target-version change.

    python -m agentforge.regression --sync-only   # register cases, no live replay
    python -m agentforge.regression               # register + replay live + record
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from jsonschema import Draft202012Validator

from agentforge.eval_case import Detector, EvalCase, Step, load_all_cases
from agentforge.eval_runner import fetch_target_version, run_case
from agentforge.target_adapter import TARGET_BASE_URL, TARGET_TIMEOUT_S

_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB = _ROOT / "evals" / "results" / "regression.db"
_CASES_DIR = _ROOT / "evals" / "cases"
_CAMPAIGN_SCHEMA = _ROOT / "contracts" / "campaign_result.schema.json"

# Higher rank = less secure. A replay ranking above its baseline is a regression.
_RANK = {"pass": 0, "partial": 1, "fail": 2}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS exploits (
  case_id TEXT PRIMARY KEY, category TEXT, severity TEXT, invariant TEXT,
  owasp_refs TEXT, case_json TEXT, baseline_result TEXT,
  first_version TEXT, first_seen_at TEXT,
  status TEXT, last_result TEXT, last_version TEXT, last_checked_at TEXT
);
CREATE TABLE IF NOT EXISTS runs (
  run_id TEXT PRIMARY KEY, target_version TEXT, started_at TEXT, finished_at TEXT,
  checked INTEGER, reproduces INTEGER, regressed INTEGER, fixed INTEGER, errors INTEGER
);
CREATE TABLE IF NOT EXISTS run_results (
  run_id TEXT, case_id TEXT, result TEXT, invariant_violated INTEGER,
  status TEXT, reappeared INTEGER, checked_at TEXT
);
"""


# --------------------------------------------------------------------------- #
# serialization (freeze an EvalCase into the versioned corpus)
# --------------------------------------------------------------------------- #

def _detector_dict(d: Detector) -> dict[str, Any]:
    return {"signals": d.signals, "kind": d.kind, "patterns": list(d.patterns), "ignore_case": d.ignore_case}


def _step_dict(s: Step) -> dict[str, Any]:
    out: dict[str, Any] = {
        "step_id": s.step_id, "patient_id": s.patient_id, "session": s.session,
        "input_sequence": [dict(m) for m in s.input_sequence],
    }
    if s.detector is not None:
        out["detector"] = _detector_dict(s.detector)
    return out


def case_to_dict(c: EvalCase) -> dict[str, Any]:
    """Round-trippable, schema-valid dict of an EvalCase for durable storage."""
    return {
        "schema_version": "1.0.0", "case_id": c.case_id, "category": c.category,
        "subcategory": c.subcategory, "owasp_refs": list(c.owasp_refs), "description": c.description,
        "test_type": c.test_type, "invariant": c.invariant, "expected_safe_behavior": c.expected_safe_behavior,
        "severity": c.severity, "exploitability": c.exploitability, "add_to_regression": c.add_to_regression,
        "requires_judge": c.requires_judge, "expected_result": c.expected_result,
        "steps": [_step_dict(s) for s in c.steps],
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# --------------------------------------------------------------------------- #
# db
# --------------------------------------------------------------------------- #

def connect(db_path: str | Path = _DEFAULT_DB) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def register_from_cases(conn: sqlite3.Connection, cases: list[EvalCase]) -> int:
    """Register/refresh the confirmed-exploit corpus from the add_to_regression
    cases. The baseline is the case's expected_result — the frozen point the
    replay is compared against. Returns how many exploits are registered."""
    n = 0
    for c in cases:
        if not c.add_to_regression:
            continue
        conn.execute(
            """
            INSERT INTO exploits (case_id, category, severity, invariant, owasp_refs, case_json,
                                  baseline_result, first_seen_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'registered')
            ON CONFLICT(case_id) DO UPDATE SET
                category=excluded.category, severity=excluded.severity, invariant=excluded.invariant,
                owasp_refs=excluded.owasp_refs, case_json=excluded.case_json,
                baseline_result=excluded.baseline_result
            """,
            (c.case_id, c.category, c.severity, c.invariant, json.dumps(list(c.owasp_refs)),
             json.dumps(case_to_dict(c)), c.expected_result, _now()),
        )
        n += 1
    conn.commit()
    return n


# --------------------------------------------------------------------------- #
# classification + run
# --------------------------------------------------------------------------- #

@dataclass
class Outcome:
    case_id: str
    category: str
    baseline: str
    result: str
    status: str              # regressed | reproduces | fixed | stable | error
    reappeared: bool
    invariant_violated: bool


@dataclass
class RunSummary:
    run_id: str
    target_version: str
    started_at: str
    finished_at: str
    outcomes: list[Outcome] = field(default_factory=list)
    cost: dict[str, Any] = field(default_factory=lambda: {"tokens": 0, "usd": 0.0})

    def _count(self, status: str) -> int:
        return sum(1 for o in self.outcomes if o.status == status)

    @property
    def checked(self) -> int:
        return len(self.outcomes)

    @property
    def alerts(self) -> list[Outcome]:
        """Regressions + reappearances — the entries a human/Orchestrator must see."""
        return [o for o in self.outcomes if o.status == "regressed" or o.reappeared]


def classify(baseline: str, current: str, previous: str | None) -> tuple[str, bool]:
    """Compare a replay result to the frozen baseline (and the previous run).

    Returns (status, reappeared). `reappeared` means the exploit was more secure
    last run and is now less secure — a vuln that came back.
    """
    if current not in _RANK:
        return "error", False
    b, c = _RANK[baseline], _RANK[current]
    reappeared = previous in _RANK and _RANK[previous] < c
    if c > b:
        return "regressed", reappeared
    if c < b:
        return "fixed", reappeared
    return ("reproduces" if baseline == "fail" else "stable"), reappeared


def run_regression(
    conn: sqlite3.Connection,
    *,
    base_url: str | None = None,
    client: httpx.Client | None = None,
    category: str | None = None,
    replay_fn: Callable[..., Any] = run_case,
    fetch_version: bool = True,
) -> RunSummary:
    """Replay every registered exploit against the live target and record the run.

    Replay is deterministic (`run_case` with no Judge). `replay_fn` is injectable
    so tests can drive it without the network.
    """
    rows = conn.execute(
        "SELECT * FROM exploits" + (" WHERE category = ?" if category else ""),
        (category,) if category else (),
    ).fetchall()

    owns = client is None
    http = client or httpx.Client(base_url=base_url or TARGET_BASE_URL, timeout=TARGET_TIMEOUT_S)
    version = (fetch_target_version(client=http) if fetch_version else "unknown") if rows else "unknown"
    summary = RunSummary(run_id=str(uuid.uuid4()), target_version=version, started_at=_now(), finished_at="")
    total_tokens, total_usd = 0, 0.0

    try:
        for row in rows:
            case = EvalCase.from_dict(json.loads(row["case_json"]))
            res = replay_fn(case, client=http)
            current = res.result
            status, reappeared = classify(row["baseline_result"], current, row["last_result"])
            total_tokens += int(res.cost.get("tokens", 0))
            total_usd += float(res.cost.get("usd", 0.0))
            summary.outcomes.append(Outcome(
                case_id=row["case_id"], category=row["category"], baseline=row["baseline_result"],
                result=current, status=status, reappeared=reappeared, invariant_violated=(current == "fail"),
            ))
            conn.execute(
                """UPDATE exploits SET status=?, last_result=?, last_version=?, last_checked_at=?,
                       first_version=COALESCE(first_version, ?) WHERE case_id=?""",
                (status, current, version, _now(), version, row["case_id"]),
            )
            conn.execute(
                "INSERT INTO run_results (run_id, case_id, result, invariant_violated, status, reappeared, checked_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (summary.run_id, row["case_id"], current, int(current == "fail"), status, int(reappeared), _now()),
            )
    finally:
        if owns:
            http.close()

    summary.finished_at = _now()
    summary.cost = {"tokens": total_tokens, "usd": round(total_usd, 6)}
    conn.execute(
        "INSERT INTO runs (run_id, target_version, started_at, finished_at, checked, reproduces, regressed, fixed, errors)"
        " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (summary.run_id, version, summary.started_at, summary.finished_at, summary.checked,
         summary._count("reproduces"), summary._count("regressed"), summary._count("fixed"), summary._count("error")),
    )
    conn.commit()
    return summary


def to_campaign_result(summary: RunSummary) -> dict[str, Any]:
    """Emit a CampaignResult (contracts/campaign_result.schema.json) for the
    Orchestrator, and validate it."""
    reproduces = summary._count("reproduces")
    cr: dict[str, Any] = {
        "schema_version": "1.0.0",
        "directive_id": summary.run_id,
        "attempts_run": summary.checked,
        "confirmed_exploits": reproduces,
        "regressions_detected": len(summary.alerts),
        "total_cost": summary.cost,
        "completed_at": summary.finished_at or _now(),
    }
    if summary.cost["usd"] > 0:
        cr["signal_yield"] = round(reproduces / summary.cost["usd"], 4)
    schema = json.loads(_CAMPAIGN_SCHEMA.read_text(encoding="utf-8"))
    errors = list(Draft202012Validator(schema).iter_errors(cr))
    if errors:
        raise ValueError(f"CampaignResult failed schema validation: {errors[0].message}")
    return cr


# --------------------------------------------------------------------------- #
# cli
# --------------------------------------------------------------------------- #

def _print_summary(summary: RunSummary) -> None:
    print("\n=== regression run ===")
    width = max((len(o.case_id) for o in summary.outcomes), default=0)
    for o in sorted(summary.outcomes, key=lambda o: (o.status != "regressed", not o.reappeared)):
        flag = ""
        if o.status == "regressed":
            flag = "  <!> REGRESSED"
        elif o.reappeared:
            flag = "  <!> REAPPEARED"
        elif o.status == "fixed":
            flag = "  [fixed]"
        print(f"  {o.case_id:<{width}}  {o.status:<11} (baseline {o.baseline} -> {o.result}){flag}")
    a = summary.alerts
    print(f"\n  {summary.checked} exploit(s) | {summary._count('reproduces')} still reproduce | {len(a)} alert(s)")
    print(f"  target version: {summary.target_version} | cost: ${summary.cost['usd']:.4f}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentforge.regression", description="Deterministic regression harness")
    parser.add_argument("--db", type=Path, default=_DEFAULT_DB)
    parser.add_argument("--cases-dir", type=Path, default=_CASES_DIR)
    parser.add_argument("--category", help="replay only this attack category")
    parser.add_argument("--base-url", help="override the target base URL")
    parser.add_argument("--sync-only", action="store_true", help="register the corpus, no live replay")
    parser.add_argument("--list", action="store_true", help="list the registered exploit corpus + status")
    args = parser.parse_args(argv)

    conn = connect(args.db)
    n = register_from_cases(conn, load_all_cases(args.cases_dir))
    print(f"registered {n} exploit(s) in the corpus ({args.db})")

    if args.list or args.sync_only:
        for row in conn.execute("SELECT case_id, category, baseline_result, status, last_result FROM exploits"):
            print(f"  {row['case_id']:<48} {row['category']:<18} baseline={row['baseline_result']:<7} "
                  f"status={row['status']} last={row['last_result']}")
        return 0

    summary = run_regression(conn, base_url=args.base_url, category=args.category)
    _print_summary(summary)
    print("\nCampaignResult:", json.dumps(to_campaign_result(summary)))
    return 3 if summary.alerts else 0  # non-zero exit when a regression/reappearance is found


if __name__ == "__main__":
    raise SystemExit(main())
