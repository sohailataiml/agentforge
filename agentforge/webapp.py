"""AgentForge Console — a web app over the platform.

A thin FastAPI layer that reuses everything already built: the dashboard
renderer for results, the eval runner to attack the target on demand, and the
Red Team agent to generate + execute a live attack. The demo patients are
synthetic test records, so it is safe to deploy (e.g. on Render).

Viewing is public; the **action** endpoints (`/api/run`, `/api/redteam`) trigger
paid LLM calls on the server's keys, so they are gated behind an operator token
when `CONSOLE_TOKEN` is set — otherwise a public console is exactly the
unbounded-cost hole this platform hunts for. When `CONSOLE_TOKEN` is unset (local
dev) the actions are open.

    pip install -e ".[web]"
    python -m agentforge.webapp            # -> http://127.0.0.1:8000
    # deploy: uvicorn agentforge.webapp:app --host 0.0.0.0 --port $PORT

Endpoints are plain `def` (FastAPI runs them in a threadpool) so the blocking
target/provider calls don't stall the event loop.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from agentforge.eval_case import load_all_cases
from agentforge.eval_runner import run_suite, write_results_jsonl
from agentforge.judge import JUDGE_MODEL
from agentforge.red_team import build_directive, run_directive
from agentforge.regression import (
    connect as regression_connect,
    register_from_cases,
    run_regression,
    to_campaign_result,
)
from agentforge.red_team_client import RED_TEAM_MODEL, RedTeamError, red_team_configured
from agentforge.rubrics import CATEGORIES
from agentforge.target_adapter import TARGET_BASE_URL
from evals.dashboard import (
    _RESULTS_DIR,
    _category_breakdown,
    _tile,
    case_index,
    load_runs,
    results_table,
)
from evals.dashboard import _CSS as DASH_CSS

app = FastAPI(title="AgentForge Console")

# Operator token gating the paid action endpoints. Unset -> actions open (local).
CONSOLE_TOKEN = os.environ.get("CONSOLE_TOKEN")

# Synthetic OpenEMR demo patient (Phil Belford) — test data, no real PHI.
DEMO_PATIENT_ID = "a2345ab2-477b-4b59-b7be-7e82aa7f9d8c"

# Canned, ready-to-run attack directives the console can load, expand, and fire —
# so a demo doesn't depend on ad-hoc typing. Each mirrors an AttackDirective.
PREPARED_DIRECTIVES = [
    {
        "id": "cross-patient-boundary",
        "label": "Cross-patient boundary test — data_exfiltration",
        "attack_category": "data_exfiltration",
        "subcategory": "a synthetic cross-patient boundary test",
        "strategy": "novel",
        "patient_id": DEMO_PATIENT_ID,
        "token_budget": 512,   # small demo budget
        "max_turns": 2,        # short
        "owasp_refs": ["LLM02", "A01"],
    },
]


def _prepared(directive_id: str) -> dict[str, Any] | None:
    return next((d for d in PREPARED_DIRECTIVES if d["id"] == directive_id), None)

# One run at a time — an in-memory job the frontend polls.
_RUN_LOCK = threading.Lock()
_RUN_STATE: dict[str, Any] = {"status": "idle", "started_at": None, "finished_at": None, "summary": None, "error": None}

# The regression harness is a separate background job (deterministic replay).
_REGRESSION_LOCK = threading.Lock()
_REGRESSION_STATE: dict[str, Any] = {
    "status": "idle", "started_at": None, "finished_at": None,
    "summary": None, "outcomes": None, "campaign": None, "error": None,
}


def _require_token(token: str | None) -> None:
    if CONSOLE_TOKEN and token != CONSOLE_TOKEN:
        raise HTTPException(status_code=401, detail="invalid or missing operator token")


def _judge_configured() -> bool:
    return bool(os.environ.get("JUDGE_ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_API_KEY"))


# --------------------------------------------------------------------------- #
# rendered fragments (reuse the dashboard renderer)
# --------------------------------------------------------------------------- #

def _console_body() -> str:
    runs = load_runs()
    if not runs:
        return (
            '<div class="empty">No runs yet. Click <b>Run attack suite</b> to attack the '
            'live target, or trigger a single Red Team attack below.</div>'
        )
    latest = runs[-1]
    cases = case_index()
    categories = sorted({r["category"] for r in latest.records})
    tiles = "".join([
        _tile(len(latest.records), "cases run"),
        _tile(latest.exploits, "exploits confirmed", "bad" if latest.exploits else "ok"),
        _tile(latest.surprises, "surprises", "warn" if latest.surprises else ""),
        _tile(len(categories), "categories"),
        _tile(f"${latest.usd:.4f}", "run cost"),
        _tile(f"{latest.tokens:,}", "tokens"),
    ])
    return (
        f'<div class="tiles">{tiles}</div>'
        f'<h2 class="sec">Results by category</h2>{_category_breakdown(latest)}'
        f'<h2 class="sec">Latest run — {len(latest.records)} cases '
        '<span class="hint">click a row for the transcript</span></h2>'
        f'{results_table(latest.records, cases)}'
    )


def _redteam_panel() -> str:
    options = "".join(f'<option value="{c}">{c}</option>' for c in CATEGORIES)
    disabled = "" if red_team_configured() else "disabled"
    warn = "" if red_team_configured() else '<div class="warn-note">Set GROQ_API_KEY to enable live attack generation.</div>'
    return (
        '<section class="panel p-rt"><header class="panel-head"><div class="num">3</div>'
        '<div><h2>Red Team</h2><p class="sub">Generate a novel attack on an open model and execute it '
        'live — with automatic OpenRouter failover and an independent Judge verdict.</p></div></header>'
        f'{warn}'
        # prepared directive: choose from dropdown -> expands to show the directive -> run
        '<div class="rt-prepared"><label class="muted">Prepared directive '
        '<select id="rt-directive"><option value="">— none (ad-hoc below) —</option></select></label>'
        '<div id="rt-directive-detail"></div></div>'
        # ad-hoc controls
        '<div class="rt-adhoc-label muted">…or ad-hoc:</div>'
        f'<div class="rt-controls"><select id="rt-cat">{options}</select>'
        '<label class="chk" title="Uses malicious-intent framing that the safety-tuned '
        'primary (Groq) refuses, forcing failover to the OpenRouter uncensored model">'
        '<input type="checkbox" id="rt-hostile"> hostile framing (force Groq refusal → OpenRouter)</label>'
        f'<button id="rt-go" onclick="redTeam()" {disabled}>Generate &amp; attack</button>'
        '<span id="rt-status" class="muted"></span></div>'
        '<div id="rt-out"></div></section>'
    )


def _regression_panel() -> str:
    return (
        '<section class="panel p-reg"><header class="panel-head"><div class="num">2</div>'
        '<div><h2>Regression Harness</h2><p class="sub">Deterministic replay of confirmed exploits '
        '— no LLM, asserts the violated invariant (not a string), and flags regressions &amp; '
        'reappearances against the live target.</p></div></header>'
        '<div class="rt-controls">'
        '<button id="reg-go" onclick="runRegression()">Run regression</button>'
        '<span id="reg-status" class="muted"></span></div>'
        '<div id="reg-out"></div></section>'
    )


# --------------------------------------------------------------------------- #
# routes
# --------------------------------------------------------------------------- #

@app.get("/api/config")
def config() -> JSONResponse:
    return JSONResponse({
        "target_url": TARGET_BASE_URL,
        "judge_model": JUDGE_MODEL,
        "judge_configured": _judge_configured(),
        "red_team_model": RED_TEAM_MODEL,
        "red_team_configured": red_team_configured(),
        "token_required": bool(CONSOLE_TOKEN),
        "categories": list(CATEGORIES),
    })


@app.get("/api/console-body", response_class=HTMLResponse)
def console_body() -> str:
    return _console_body()


@app.get("/api/directives")
def directives() -> JSONResponse:
    return JSONResponse({"directives": PREPARED_DIRECTIVES})


@app.get("/api/cases")
def cases_info() -> JSONResponse:
    """The eval suite's directive/case info — what the attack suite will exercise."""
    from agentforge.eval_case import load_all_cases

    cases = [
        {
            "case_id": c.case_id, "category": c.category, "subcategory": c.subcategory,
            "test_type": c.test_type, "severity": c.severity, "expected_result": c.expected_result,
            "requires_judge": c.requires_judge, "invariant": c.invariant, "owasp_refs": list(c.owasp_refs),
        }
        for c in load_all_cases(_cases_dir())
    ]
    return JSONResponse({"cases": cases})


@app.get("/api/run/status")
def run_status() -> JSONResponse:
    return JSONResponse(_RUN_STATE)


@app.post("/api/clear")
def clear_runs(x_console_token: str | None = Header(default=None)) -> JSONResponse:
    """Clear the previous run(s) from the console — archives the run-log JSONL
    files so the results view resets to the empty state (recoverable, not deleted).
    Token-gated so a public console can't be wiped by a visitor."""
    _require_token(x_console_token)
    import glob as _glob
    import shutil
    from pathlib import Path as _Path

    archive = _RESULTS_DIR / "archive"
    archive.mkdir(parents=True, exist_ok=True)
    cleared = 0
    for f in _glob.glob(str(_RESULTS_DIR / "run-*.jsonl")):
        dest = archive / _Path(f).name
        if dest.exists():
            dest = archive / f"{_Path(f).stem}-{cleared}.jsonl"
        shutil.move(f, str(dest))
        cleared += 1
    _RUN_STATE.update(status="idle", started_at=None, finished_at=None, summary=None, error=None)
    return JSONResponse({"cleared": cleared})


def _do_run(category: str | None, use_judge: bool) -> None:
    try:
        cases = load_all_cases(_cases_dir())
        if category:
            cases = [c for c in cases if c.category == category]
        judge_fn = None
        if use_judge:
            from agentforge.judge import judge_attempt

            judge_fn = judge_attempt
        # When the Judge is enabled in the console, score EVERY case (judge_all) so
        # confirmed exploits also carry an authoritative, confidence-scored verdict —
        # not just the requires_judge cases. (The CLI keeps the cheaper default.)
        results = run_suite(cases, judge=judge_fn, judge_all=bool(judge_fn))
        out = _RESULTS_DIR / f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.jsonl"
        write_results_jsonl(results, out)
        exploits = sum(1 for r in results if r.result == "fail")
        surprises = sum(1 for r in results if r.surprise)
        _RUN_STATE.update(
            status="done",
            finished_at=datetime.now(timezone.utc).isoformat(),
            summary={"cases": len(results), "exploits": exploits, "surprises": surprises},
        )
    except Exception as exc:  # noqa: BLE001 — surface any run failure to the UI
        _RUN_STATE.update(status="error", finished_at=datetime.now(timezone.utc).isoformat(), error=str(exc))
    finally:
        _RUN_LOCK.release()


def _cases_dir():
    from pathlib import Path

    return Path(__file__).resolve().parent.parent / "evals" / "cases"


@app.post("/api/run")
def start_run(category: str | None = None, judge: bool = False,
              x_console_token: str | None = Header(default=None)) -> JSONResponse:
    _require_token(x_console_token)
    if not _RUN_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="a run is already in progress")
    _RUN_STATE.update(status="running", started_at=datetime.now(timezone.utc).isoformat(),
                      finished_at=None, summary=None, error=None)
    threading.Thread(target=_do_run, args=(category, judge), daemon=True).start()
    return JSONResponse({"status": "running"})


@app.post("/api/redteam")
def red_team(category: str = "prompt_injection", hostile: bool = False, directive_id: str | None = None,
             patient_id: str = DEMO_PATIENT_ID,
             x_console_token: str | None = Header(default=None)) -> JSONResponse:
    _require_token(x_console_token)
    if not red_team_configured():
        raise HTTPException(status_code=400, detail="Red Team not configured — set GROQ_API_KEY")

    if directive_id:  # run a prepared directive verbatim
        pd = _prepared(directive_id)
        if not pd:
            raise HTTPException(status_code=400, detail=f"unknown directive {directive_id!r}")
        directive = build_directive(
            pd["attack_category"], pd["subcategory"], pd["owasp_refs"],
            strategy_hint=pd["strategy"], token_budget=pd["token_budget"], max_turns=pd["max_turns"],
        )
        pid = pd["patient_id"]
    else:  # ad-hoc: category + hostile toggle
        if category not in CATEGORIES:
            raise HTTPException(status_code=400, detail=f"unknown category {category!r}")
        directive = build_directive(category, "console-adhoc", ["LLM01"], max_turns=1)
        pid = patient_id

    try:
        campaign = run_directive(directive, pid, hostile=hostile)
    except RedTeamError as exc:
        # e.g. both Groq refused AND the OpenRouter fallback was rate-limited/errored —
        # surface a clean JSON error the UI can show, not a raw 500.
        raise HTTPException(status_code=502, detail=f"attack generation failed: {exc}") from exc
    rec = campaign.records[0]
    if rec.attempt is None:
        return JSONResponse({"dropped_reason": rec.dropped_reason})

    # Judge the attempt so the panel shows a result + rationale. Best-effort: a
    # Judge outage must not lose the attack/transcript we already have.
    verdict, judge_note = None, None
    if _judge_configured():
        try:
            from agentforge.judge import JudgeInput, judge_attempt
            from agentforge.red_team import _JUDGE_INVARIANT

            v = judge_attempt(JudgeInput(
                attack_category=rec.attempt["attack_category"],
                invariant=_JUDGE_INVARIANT.format(category=rec.attempt["attack_category"]),
                expected_safe_behavior=rec.attempt["expected_safe_behavior"],
                input_sequence=rec.attempt["input_sequence"],
                target_transcript=rec.attempt["target_transcript"],
                attempt_id=rec.attempt["attempt_id"],
            ))
            verdict = v.verdict
        except Exception as exc:  # noqa: BLE001 — judging is best-effort in the console
            judge_note = f"judge unavailable: {exc}"

    return JSONResponse({
        "attack": rec.attempt["input_sequence"],
        "transcript": rec.attempt["target_transcript"],
        "expected_safe_behavior": rec.attempt["expected_safe_behavior"],
        "cost": rec.attempt["cost"],
        "model": rec.served_model or RED_TEAM_MODEL,
        "fell_back": rec.fell_back,
        "fallback_reason": rec.fallback_reason,
        "verdict": verdict,
        "judge_note": judge_note,
    })


def _do_regression() -> None:
    try:
        conn = regression_connect()  # persistent corpus under evals/results/ (git-ignored)
        try:
            register_from_cases(conn, load_all_cases(_cases_dir()))
            summary = run_regression(conn)  # deterministic replay, no Judge, no LLM on our side
            # enrich each outcome with severity + invariant from the corpus for display
            meta = {r["case_id"]: dict(r) for r in conn.execute("SELECT case_id, severity, invariant FROM exploits")}
            outcomes = [
                {
                    "case_id": o.case_id, "category": o.category, "baseline": o.baseline, "result": o.result,
                    "status": o.status, "reappeared": o.reappeared, "invariant_violated": o.invariant_violated,
                    "severity": meta.get(o.case_id, {}).get("severity", ""),
                    "invariant": meta.get(o.case_id, {}).get("invariant", ""),
                }
                for o in summary.outcomes
            ]
        finally:
            conn.close()
        _REGRESSION_STATE.update(
            status="done", finished_at=datetime.now(timezone.utc).isoformat(),
            outcomes=outcomes, campaign=to_campaign_result(summary),
            summary={
                "checked": summary.checked, "reproduces": summary._count("reproduces"),
                "regressed": summary._count("regressed"), "fixed": summary._count("fixed"),
                "stable": summary._count("stable"), "alerts": len(summary.alerts),
                "target_version": summary.target_version, "cost": summary.cost,
            },
        )
    except Exception as exc:  # noqa: BLE001 — surface any replay failure to the UI
        _REGRESSION_STATE.update(status="error", finished_at=datetime.now(timezone.utc).isoformat(), error=str(exc))
    finally:
        _REGRESSION_LOCK.release()


@app.get("/api/regression/status")
def regression_status() -> JSONResponse:
    return JSONResponse(_REGRESSION_STATE)


@app.post("/api/regression")
def start_regression(x_console_token: str | None = Header(default=None)) -> JSONResponse:
    _require_token(x_console_token)
    if not _REGRESSION_LOCK.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="a regression run is already in progress")
    _REGRESSION_STATE.update(status="running", started_at=datetime.now(timezone.utc).isoformat(),
                             finished_at=None, summary=None, outcomes=None, campaign=None, error=None)
    threading.Thread(target=_do_regression, daemon=True).start()
    return JSONResponse({"status": "running"})


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (_PAGE.replace("{{CSS}}", DASH_CSS).replace("{{BODY}}", _console_body())
            .replace("{{REG}}", _regression_panel()).replace("{{RT}}", _redteam_panel()))


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentForge Console</title>
<style>{{CSS}}
.appbar { display:flex; flex-wrap:wrap; align-items:center; gap:12px 18px; margin:0 0 18px; }
.appbar h1 { margin:0; font-size:20px; } .appbar h1 b { color:var(--accent); }
.appbar .cfg { margin-left:auto; display:flex; gap:8px; flex-wrap:wrap; font-size:12px; }
.pill { border:1px solid var(--line); border-radius:999px; padding:3px 10px; color:var(--muted); }
.pill.on { color:var(--ok); border-color:#1c3a24; background:#0e1c12; }
.pill.off { color:var(--faint); }
button { background:var(--accent); color:#0a0d14; border:0; border-radius:8px; padding:9px 16px; font-weight:600; cursor:pointer; font-size:13px; }
button:hover { filter:brightness(1.08); } button:disabled { opacity:.4; cursor:not-allowed; }
button.ghost { background:var(--panel); color:var(--text); border:1px solid var(--line); }
.controls { display:flex; gap:10px; align-items:center; margin:0 0 20px; flex-wrap:wrap; }
select { background:var(--panel); color:var(--text); border:1px solid var(--line); border-radius:8px; padding:8px 10px; font-size:13px; }
.token { background:var(--panel); color:var(--text); border:1px solid var(--line); border-radius:8px; padding:6px 10px; font-size:12px; width:150px; }
label.chk { color:var(--muted); font-size:13px; display:flex; gap:6px; align-items:center; }
.muted { color:var(--muted); font-size:12.5px; } .hint { color:var(--faint); text-transform:none; letter-spacing:0; font-weight:400; }
.empty { color:var(--muted); border:1px dashed var(--line); border-radius:10px; padding:28px; text-align:center; }
.panel { position:relative; background:var(--panel); border:1px solid var(--line); border-radius:16px; padding:22px 24px 24px; margin:0 0 22px; }
.panel::before { content:''; position:absolute; left:0; top:0; bottom:0; width:3px; border-radius:16px 0 0 16px; background:var(--accent); }
.panel.p-reg::before { background:var(--judge); } .panel.p-rt::before { background:var(--surprise); }
.panel-head { display:flex; align-items:flex-start; gap:14px; margin:0 0 18px; padding-bottom:16px; border-bottom:1px solid var(--line); }
.panel-head .num { flex:0 0 auto; width:30px; height:30px; border-radius:9px; display:grid; place-items:center; font-weight:700; font-size:14px; color:var(--accent); border:1px solid var(--line); background:var(--panel-2); }
.panel.p-reg .panel-head .num { color:var(--judge); } .panel.p-rt .panel-head .num { color:var(--surprise); }
.panel-head h2 { margin:0; font-size:16px; } .panel-head .sub { margin:3px 0 0; color:var(--muted); font-size:12.5px; max-width:74ch; }
.panel .tiles { margin-top:6px; }
.rt-controls { display:flex; gap:10px; align-items:center; margin-bottom:12px; flex-wrap:wrap; }
#rt-out .turn { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:10px 14px; margin-top:8px; }
#rt-out .turn .lbl { color:var(--accent); font-size:11px; text-transform:uppercase; letter-spacing:.7px; }
#rt-out .turn.target .lbl { color:var(--ok); }
#rt-out .turn.fallback { border-color:var(--surprise); background:#1a1405; }
#rt-out .turn.fallback .lbl { color:var(--surprise); }
#rt-out .turn.verdict { border-color:var(--judge); }
#rt-out .turn.verdict .lbl { color:var(--judge); }
#rt-out .turn.verdict .vhead { margin-bottom:6px; font-size:12.5px; color:var(--muted); }
.rt-prepared { margin-bottom:6px; }
.rt-adhoc-label { margin:10px 0 4px; }
.directive-card { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-top:10px; max-width:560px; }
.directive-card .drow { display:flex; justify-content:space-between; gap:16px; padding:5px 0; border-bottom:1px solid var(--line); font-size:13px; }
.directive-card .drow:last-of-type { border-bottom:0; }
.directive-card .drow span { color:var(--muted); }
.directive-card button { margin-top:12px; }
details.cases { margin:0 0 18px; }
details.cases summary { cursor:pointer; color:var(--muted); font-size:13px; }
details.cases table { width:100%; border-collapse:collapse; margin-top:10px; font-size:12.5px; }
details.cases td, details.cases th { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
details.cases th { color:var(--faint); font-size:11px; text-transform:uppercase; letter-spacing:.6px; }
details.cases .inv { color:var(--muted); }
#rt-out pre { margin:6px 0 0; white-space:pre-wrap; word-break:break-word; font-size:12.5px; color:#c7cede; }
.reg-table { width:100%; border-collapse:collapse; margin-top:12px; font-size:12.5px; }
.reg-table td, .reg-table th { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
.reg-table th { color:var(--faint); font-size:11px; text-transform:uppercase; letter-spacing:.6px; }
.reg-table tr.alert td { background:#1a0f0e; }
.reg-table .inv { color:var(--muted); max-width:360px; }
.reg-json { margin:10px 0 0; white-space:pre-wrap; word-break:break-word; font-size:12px; color:#c7cede; background:var(--panel-2); border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
.warn-note { color:var(--surprise); font-size:12.5px; margin-bottom:10px; }
.spin { display:inline-block; width:12px; height:12px; border:2px solid var(--line); border-top-color:var(--accent); border-radius:50%; animation:spin .7s linear infinite; vertical-align:middle; }
@keyframes spin { to { transform:rotate(360deg); } }
</style></head>
<body><div class="wrap">
<div class="appbar">
  <h1><b>AgentForge</b> Console</h1>
  <input id="op-token" class="token" type="password" placeholder="operator token" style="display:none">
  <div class="cfg" id="cfg"></div>
</div>

<section class="panel p-eval">
  <header class="panel-head"><div class="num">1</div>
    <div><h2>Eval Suite</h2><p class="sub">Deterministic + Judge-scored attacks across the OWASP LLM
    categories — run the versioned case suite against the live target.</p></div></header>
  <div class="controls">
    <select id="run-cat"><option value="">all categories</option></select>
    <label class="chk"><input type="checkbox" id="run-judge"> use Judge</label>
    <button id="run-btn" onclick="runSuite()">Run attack suite</button>
    <button class="ghost" onclick="clearRun()">Clear previous run</button>
    <span id="run-status" class="muted"></span>
  </div>
  <details class="cases"><summary>Suite directives / cases (<span id="suite-count">…</span>) — what the attack suite exercises</summary><div id="suite-cases"></div></details>
  <div id="console-body">{{BODY}}</div>
</section>
{{REG}}
{{RT}}

<footer>AgentForge operator console — synthetic demo patients; paid actions gated by operator token.</footer>
</div>
<script>
const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));

function authHeaders() {
  const t = document.getElementById('op-token').value;
  if (t) localStorage.setItem('af_token', t);
  return t ? {'X-Console-Token': t} : {};
}

async function loadConfig() {
  const c = await (await fetch('/api/config')).json();
  document.getElementById('cfg').innerHTML =
    `<span class="pill">target ${esc(new URL(c.target_url).host)}</span>` +
    `<span class="pill ${c.red_team_configured?'on':'off'}">Red Team ${c.red_team_configured?'ready':'no key'}</span>` +
    `<span class="pill ${c.judge_configured?'on':'off'}">Judge ${c.judge_configured?'ready':'no credits?'}</span>`;
  const sel = document.getElementById('run-cat');
  c.categories.forEach(cat => { const o=document.createElement('option'); o.value=o.textContent=cat; sel.appendChild(o); });
  document.getElementById('run-judge').disabled = !c.judge_configured;
  if (c.token_required) {
    const el = document.getElementById('op-token');
    el.style.display = 'inline-block';
    el.value = localStorage.getItem('af_token') || '';
  }
}

// event delegation: expand transcript rows even after innerHTML swaps
document.addEventListener('click', e => {
  const row = e.target.closest('tr.case');
  if (!row) return;
  const d = document.getElementById('detail-' + row.dataset.cid);
  if (d) { d.classList.toggle('open'); const a=row.querySelector('.arrow'); if(a) a.textContent = d.classList.contains('open')?'\\u25be':'\\u25b8'; }
});

async function refresh() {
  document.getElementById('console-body').innerHTML = await (await fetch('/api/console-body')).text();
}

async function clearRun() {
  const status = document.getElementById('run-status');
  const r = await fetch('/api/clear', {method:'POST', headers: authHeaders()});
  if (r.status === 401) { status.textContent = 'operator token required/invalid'; return; }
  if (!r.ok) { status.textContent = 'clear failed'; return; }
  const d = await r.json();
  await refresh();                       // console-body is now the empty state
  status.textContent = `cleared ${d.cleared} previous run(s)`;
}

async function runSuite() {
  const cat = document.getElementById('run-cat').value;
  const judge = document.getElementById('run-judge').checked;
  const btn = document.getElementById('run-btn'); const status = document.getElementById('run-status');
  btn.disabled = true;
  const r = await fetch(`/api/run?judge=${judge}` + (cat?`&category=${encodeURIComponent(cat)}`:''), {method:'POST', headers: authHeaders()});
  if (r.status === 401) { status.textContent = 'operator token required/invalid'; btn.disabled=false; return; }
  if (r.status === 409) { status.textContent = 'a run is already in progress'; btn.disabled=false; return; }
  status.innerHTML = '<span class="spin"></span> attacking the live target…';
  poll(btn, status);
}

async function poll(btn, status) {
  const s = await (await fetch('/api/run/status')).json();
  if (s.status === 'running') { setTimeout(() => poll(btn, status), 2000); return; }
  btn.disabled = false;
  if (s.status === 'error') { status.textContent = 'run error: ' + s.error; return; }
  const sum = s.summary || {};
  status.textContent = `done — ${sum.cases} cases, ${sum.exploits} exploit(s), ${sum.surprises} surprise(s)`;
  refresh();
}

function renderAttackResult(d, statusEl, out) {
  if (d.dropped_reason) { statusEl.textContent=''; out.innerHTML = `<div class="turn"><div class="lbl">dropped by egress screen</div><pre>${esc(d.dropped_reason)}</pre></div>`; return; }
  statusEl.textContent = `generated on ${esc(d.model)} · $${d.cost.usd.toFixed(4)}`;
  let html='';
  if (d.fell_back) html += `<div class="turn fallback"><div class="lbl">\\u26a0 primary refused \\u2192 OpenRouter fallback</div><pre>${esc(d.fallback_reason||'')}\nServed by uncensored model: ${esc(d.model)}</pre></div>`;
  d.attack.forEach(t => html += `<div class="turn"><div class="lbl">attack · ${esc(t.role)}</div><pre>${esc(t.content)}</pre></div>`);
  d.transcript.forEach(t => html += `<div class="turn target"><div class="lbl">target · ${esc(t.role)}</div><pre>${esc(t.content)}</pre></div>`);
  if (d.verdict) {
    const v = d.verdict;
    const cls = v.result === 'fail' ? 'bad' : (v.result === 'pass' ? 'ok' : 'warn');
    const label = v.result === 'fail' ? 'EXPLOIT — target failed' : (v.result === 'pass' ? 'held' : 'partial');
    const gate = v.escalate_to_human ? ' · escalated to human' : '';
    html += `<div class="turn verdict"><div class="lbl">judge verdict</div>`
      + `<div class="vhead"><span class="chip ${cls}">${label}</span> confidence ${v.confidence.toFixed(2)} · severity ${esc(v.severity)}${gate}</div>`
      + `<pre>${esc(v.rationale)}</pre></div>`;
  } else if (d.judge_note) {
    html += `<div class="turn"><div class="lbl">judge</div><pre>${esc(d.judge_note)}</pre></div>`;
  }
  out.innerHTML = html;
}

async function postAttack(qs, statusEl, btn) {
  const out = document.getElementById('rt-out');
  if (btn) btn.disabled = true;
  statusEl.innerHTML = '<span class="spin"></span> generating on the open model &amp; attacking…'; out.innerHTML='';
  try {
    const r = await fetch(`/api/redteam?${qs}`, {method:'POST', headers: authHeaders()});
    const d = await r.json();
    if (r.status === 401) statusEl.textContent = 'operator token required/invalid';
    else if (!r.ok) statusEl.textContent = 'error: ' + (d.detail||'failed');
    else renderAttackResult(d, statusEl, out);
  } catch (e) { statusEl.textContent = 'error: ' + e; }
  if (btn) btn.disabled = false;
}

function redTeam() {
  const cat = document.getElementById('rt-cat').value;
  const hostile = document.getElementById('rt-hostile').checked;
  postAttack(`category=${encodeURIComponent(cat)}&hostile=${hostile}`, document.getElementById('rt-status'), document.getElementById('rt-go'));
}

let DIRECTIVES = [];
async function loadDirectives() {
  const d = await (await fetch('/api/directives')).json();
  DIRECTIVES = d.directives || [];
  const sel = document.getElementById('rt-directive');
  DIRECTIVES.forEach(x => { const o=document.createElement('option'); o.value=x.id; o.textContent=x.label; sel.appendChild(o); });
  sel.addEventListener('change', () => showDirective(sel.value));
}

function showDirective(id) {
  const det = document.getElementById('rt-directive-detail');
  const d = DIRECTIVES.find(x => x.id === id);
  if (!d) { det.innerHTML=''; return; }
  det.innerHTML =
    `<div class="directive-card">
      <div class="drow"><span>attack category</span><b>${esc(d.attack_category)}</b></div>
      <div class="drow"><span>subcategory</span><b>${esc(d.subcategory)}</b></div>
      <div class="drow"><span>strategy</span><b>${esc(d.strategy)}</b></div>
      <div class="drow"><span>synthetic patient ID</span><b class="mono">${esc(d.patient_id)}</b></div>
      <div class="drow"><span>token budget</span><b>${d.token_budget}</b></div>
      <div class="drow"><span>max turns</span><b>${d.max_turns}</b></div>
      <button id="rt-dir-go" onclick="runDirective('${esc(d.id)}')">Run prepared directive</button>
      <span id="rt-dir-status" class="muted"></span>
    </div>`;
}

function runDirective(id) {
  const hostile = document.getElementById('rt-hostile').checked;
  postAttack(`directive_id=${encodeURIComponent(id)}&hostile=${hostile}`, document.getElementById('rt-dir-status'), document.getElementById('rt-dir-go'));
}

async function loadCases() {
  try {
    const cs = (await (await fetch('/api/cases')).json()).cases || [];
    document.getElementById('suite-count').textContent = cs.length;
    const rows = cs.map(c => `<tr><td class="mono">${esc(c.case_id)}</td><td>${esc(c.category)}</td>`
      + `<td>${esc(c.subcategory)}</td><td>${esc(c.test_type)}</td><td>${esc(c.severity)}</td>`
      + `<td>exp ${esc(c.expected_result)}${c.requires_judge?' · judge':''}</td>`
      + `<td class="inv">${esc(c.invariant)}</td></tr>`).join('');
    document.getElementById('suite-cases').innerHTML =
      `<table><thead><tr><th>case</th><th>category</th><th>subcategory</th><th>type</th><th>severity</th><th>expected</th><th>invariant</th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) { document.getElementById('suite-cases').textContent = 'failed to load cases'; }
}

// --- Regression Harness -------------------------------------------------
const REG_META = {
  regressed:  ['bad',  'REGRESSED'],
  reproduces: ['bad',  'reproduces'],
  fixed:      ['ok',   'fixed'],
  stable:     ['ok',   'stable'],
  error:      ['warn', 'error'],
};
function regRank(o) {
  if (o.status === 'regressed') return 4;
  if (o.reappeared) return 3;
  if (o.status === 'reproduces') return 2;
  if (o.status === 'fixed') return 1;
  return 0;
}
function tile(n, label, cls) { return `<div class="tile ${cls||''}"><div class="n">${esc(n)}</div><div class="l">${esc(label)}</div></div>`; }

async function runRegression() {
  const btn = document.getElementById('reg-go'), status = document.getElementById('reg-status');
  btn.disabled = true;
  const r = await fetch('/api/regression', {method:'POST', headers: authHeaders()});
  if (r.status === 401) { status.textContent = 'operator token required/invalid'; btn.disabled=false; return; }
  if (r.status === 409) { status.textContent = 'a regression run is already in progress'; btn.disabled=false; return; }
  if (!r.ok) { const d = await r.json().catch(()=>({})); status.textContent = 'error: ' + (d.detail||'failed'); btn.disabled=false; return; }
  status.innerHTML = '<span class="spin"></span> replaying the exploit corpus against the live target…';
  pollRegression(btn, status);
}

async function pollRegression(btn, status) {
  const s = await (await fetch('/api/regression/status')).json();
  if (s.status === 'running') { setTimeout(() => pollRegression(btn, status), 2000); return; }
  btn.disabled = false;
  if (s.status === 'error') { status.textContent = 'regression error: ' + s.error; return; }
  renderRegression(s, status);
}

function renderRegression(s, status) {
  const sum = s.summary || {}, out = document.getElementById('reg-out');
  status.textContent = `done — ${sum.checked} replayed · ${sum.reproduces} reproduce · ${sum.alerts} alert(s)`;
  const tiles = '<div class="tiles">'
    + tile(sum.checked, 'exploits replayed')
    + tile(sum.reproduces, 'still reproduce', sum.reproduces ? 'bad' : 'ok')
    + tile(sum.alerts, 'alerts', sum.alerts ? 'bad' : 'ok')
    + tile(sum.fixed, 'fixed', sum.fixed ? 'ok' : '')
    + tile('$' + ((sum.cost && sum.cost.usd) || 0).toFixed(4), 'target cost')
    + tile(sum.target_version || '?', 'target version')
    + '</div>';
  const rows = (s.outcomes || []).slice().sort((a, b) => regRank(b) - regRank(a)).map(o => {
    const [cls, label] = REG_META[o.status] || ['warn', o.status];
    const badge = (o.reappeared && o.status !== 'regressed') ? ' <span class="chip bad">reappeared</span>' : '';
    const alertRow = (o.status === 'regressed' || o.reappeared) ? ' class="alert"' : '';
    return `<tr${alertRow}>
      <td class="mono">${esc(o.case_id)}</td>
      <td>${esc(o.category)}</td>
      <td>${esc(o.severity || '')}</td>
      <td>${esc(o.baseline)} \\u2192 <b>${esc(o.result)}</b></td>
      <td><span class="chip ${cls}">${esc(label)}</span>${badge}</td>
      <td class="inv">${esc(o.invariant || '')}</td></tr>`;
  }).join('');
  out.innerHTML = tiles
    + `<table class="reg-table"><thead><tr><th>exploit</th><th>category</th><th>severity</th>`
    + `<th>baseline \\u2192 replay</th><th>status</th><th>invariant asserted</th></tr></thead><tbody>${rows}</tbody></table>`
    + `<details class="cases"><summary>CampaignResult (contract emitted to the Orchestrator)</summary>`
    + `<pre class="reg-json">${esc(JSON.stringify(s.campaign || {}, null, 2))}</pre></details>`;
}

loadConfig(); loadDirectives(); loadCases();
</script></body></html>"""


def main() -> int:
    import uvicorn

    # Render (and other PaaS) provide the port via $PORT and need 0.0.0.0.
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
