"""Observability (Phase 8) — the operational questions, answered from stored state.

No new datastore: this reads the artifacts the agents already write — the eval run
logs (`eval_result` records), the regression DB, and the VulnReport corpus — and
answers the six questions a security lead asks. The web console renders these live;
this module is the headless/CLI equivalent (and what `tests/test_observability.py`
asserts against).

    python -m agentforge.observability          # print the full dashboard
"""

from __future__ import annotations

import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_RESULTS_DIR = _ROOT / "evals" / "results"
_REPORTS_DIR = _ROOT / "reports"
_REG_DB = _RESULTS_DIR / "regression.db"

_STATUSES = ("open", "in_progress", "resolved", "wont_fix")


# --------------------------------------------------------------------------- #
# loaders
# --------------------------------------------------------------------------- #

def load_records(results_dir: Path = _RESULTS_DIR) -> list[dict[str, Any]]:
    """All eval_result records across every run log, newest file last."""
    records: list[dict[str, Any]] = []
    for log in sorted(Path(results_dir).glob("run-*.jsonl")):
        for line in log.read_text(encoding="utf-8").splitlines():
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def load_reports(reports_dir: Path = _REPORTS_DIR) -> list[dict[str, Any]]:
    out = []
    for jf in sorted(Path(reports_dir).glob("AF-*.json")):
        try:
            out.append(json.loads(jf.read_text(encoding="utf-8")))
        except json.JSONDecodeError:
            continue
    return out


def regression_runs(db_path: Path = _REG_DB) -> list[dict[str, Any]]:
    if not Path(db_path).exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT target_version, started_at, checked, reproduces, regressed, fixed "
            "FROM runs ORDER BY started_at").fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error:
        return []


# --------------------------------------------------------------------------- #
# the six questions
# --------------------------------------------------------------------------- #

def cases_per_category(records: list[dict[str, Any]]) -> dict[str, int]:
    return dict(Counter(r.get("category", "?") for r in records))


def pass_fail_by_category_version(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Pass/fail counts keyed by 'category @ version', with a resilience rate."""
    buckets: dict[str, Counter] = defaultdict(Counter)
    for r in records:
        key = f"{r.get('category', '?')} @ {r.get('target_system_version', 'unknown')}"
        buckets[key][r.get("result", "error")] += 1
    out = {}
    for key, c in buckets.items():
        graded = c["pass"] + c["fail"] + c["partial"]  # errors don't count toward the rate
        out[key] = {
            "pass": c["pass"], "fail": c["fail"], "partial": c["partial"], "error": c["error"],
            "resilience_rate": round(c["pass"] / graded, 3) if graded else None,
        }
    return out


def resilience_trend(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Per regression run over time: how many confirmed exploits still reproduce
    (lower is better), plus a resilience score = 1 - reproduces/checked."""
    trend = []
    for run in runs:
        checked = run.get("checked") or 0
        reproduces = run.get("reproduces") or 0
        trend.append({
            "version": run.get("target_version", "unknown"), "at": run.get("started_at"),
            "checked": checked, "reproduces": reproduces, "regressed": run.get("regressed") or 0,
            "resilience": round(1 - reproduces / checked, 3) if checked else None,
        })
    return trend


def vuln_status(reports: list[dict[str, Any]]) -> dict[str, Any]:
    by_status = Counter(r.get("status", "open") for r in reports)
    by_severity = Counter(r.get("severity", "?") for r in reports)
    open_high = sum(1 for r in reports
                    if r.get("status") not in ("resolved", "wont_fix") and r.get("severity") in ("critical", "high"))
    return {
        "by_status": {s: by_status.get(s, 0) for s in _STATUSES},
        "by_severity": dict(by_severity), "open_high_or_critical": open_high, "total": len(reports),
    }


def cost_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
    total_usd = sum(float((r.get("cost") or {}).get("usd", 0.0)) for r in records)
    total_tok = sum(int((r.get("cost") or {}).get("tokens", 0)) for r in records)
    n = len(records)
    per_case = total_usd / n if n else 0.0
    return {
        "cases": n, "total_usd": round(total_usd, 4), "total_tokens": total_tok,
        "per_case_usd": round(per_case, 4),
        "projected_usd_per_1k": round(per_case * 1000, 2),  # naive scaling; see AI_COST_ANALYSIS.md
    }


def agent_timeline(records: list[dict[str, Any]], reports: list[dict[str, Any]],
                   runs: list[dict[str, Any]], *, limit: int = 40) -> list[dict[str, Any]]:
    """Reconstruct who-did-what-when from the timestamps each agent stamps on its
    output — no separate event bus needed."""
    events: list[dict[str, Any]] = []
    for r in records:
        events.append({"ts": r.get("executed_at"), "agent": "Eval Runner",
                       "action": f"ran {r.get('case_id')} -> {r.get('result')}"})
        v = r.get("verdict")
        if v:
            events.append({"ts": v.get("judged_at"), "agent": "Judge",
                           "action": f"scored {r.get('case_id')} -> {v.get('result')} ({v.get('severity')})"})
    for rep in reports:
        events.append({"ts": rep.get("created_at"), "agent": "Documentation",
                       "action": f"authored {rep.get('vuln_id')} [{rep.get('severity')}]"})
    for run in runs:
        events.append({"ts": run.get("started_at"), "agent": "Regression",
                       "action": f"replayed corpus @ {run.get('target_version')}: "
                                 f"{run.get('reproduces')} reproduce, {run.get('regressed')} regressed"})
    events = [e for e in events if e["ts"]]
    events.sort(key=lambda e: e["ts"])
    return events[-limit:]


# --------------------------------------------------------------------------- #
# cli — a text dashboard
# --------------------------------------------------------------------------- #

def main(argv: list[str] | None = None) -> int:
    records, reports, runs = load_records(), load_reports(), regression_runs()

    print("=== cases per category ===")
    for cat, n in sorted(cases_per_category(records).items()):
        print(f"  {cat:<18} {n}")

    print("\n=== pass/fail by category & target version ===")
    for key, c in sorted(pass_fail_by_category_version(records).items()):
        print(f"  {key:<34} pass={c['pass']} fail={c['fail']} partial={c['partial']} "
              f"err={c['error']} resilience={c['resilience_rate']}")

    print("\n=== resilience trend (regression runs over time) ===")
    for t in resilience_trend(runs):
        print(f"  {t['at']}  v{t['version']}  {t['reproduces']}/{t['checked']} reproduce  "
              f"resilience={t['resilience']}  regressed={t['regressed']}")
    if not runs:
        print("  (no regression runs recorded yet)")

    print("\n=== vulnerability status ===")
    vs = vuln_status(reports)
    print(f"  by status:   {vs['by_status']}")
    print(f"  by severity: {vs['by_severity']}")
    print(f"  open high/critical: {vs['open_high_or_critical']}  |  total: {vs['total']}")

    print("\n=== run cost + scaling ===")
    cs = cost_summary(records)
    print(f"  {cs['cases']} cases | ${cs['total_usd']} | {cs['total_tokens']:,} tokens | "
          f"${cs['per_case_usd']}/case | ~${cs['projected_usd_per_1k']}/1k naive")

    print("\n=== per-agent action timeline (most recent) ===")
    for e in agent_timeline(records, reports, runs, limit=20):
        print(f"  {e['ts']}  [{e['agent']:<13}] {e['action']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
