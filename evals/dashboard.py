"""Generate a self-contained HTML dashboard from the eval run logs.

Reads every evals/results/run-*.jsonl the runner has written, enriches each
result with its authored case metadata (severity, test_type, invariant, OWASP
refs), and renders one static HTML file — no external assets, no network, no JS
frameworks — answering the Phase 8 observability questions: cases per category,
pass/fail by category and target version, confirmed exploits, surprises, cost,
and a run-over-run resilience trend.

The output embeds real (demo) patient identifiers and confirmed findings, so it
is written to the gitignored evals/results/ directory and kept local — it is an
operator console, not something to publish.

    python -m evals.dashboard              # -> evals/results/dashboard.html
    python -m evals.dashboard --open       # also open it in the browser
    python -m evals.dashboard --out x.html
"""

from __future__ import annotations

import argparse
import glob
import html
import json
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agentforge.eval_case import EvalCase, load_all_cases
from agentforge.target_adapter import TARGET_BASE_URL

_EVALS_DIR = Path(__file__).resolve().parent
_RESULTS_DIR = _EVALS_DIR / "results"
_CASES_DIR = _EVALS_DIR / "cases"

_RESULT_COLORS = {"pass": "ok", "fail": "bad", "partial": "warn", "error": "err"}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Run:
    path: Path
    stamp: str  # the run-<stamp>.jsonl timestamp token
    records: list[dict[str, Any]]

    @property
    def exploits(self) -> int:
        return sum(1 for r in self.records if r["result"] == "fail")

    @property
    def surprises(self) -> int:
        return sum(1 for r in self.records if r.get("surprise"))

    @property
    def errors(self) -> int:
        return sum(1 for r in self.records if r["result"] == "error")

    @property
    def usd(self) -> float:
        return sum(r["cost"]["usd"] for r in self.records)

    @property
    def tokens(self) -> int:
        return sum(r["cost"]["tokens"] for r in self.records)

    @property
    def target_version(self) -> str:
        versions = {r.get("target_system_version", "unknown") for r in self.records}
        return ", ".join(sorted(versions)) or "unknown"

    @property
    def executed_at(self) -> str:
        stamps = [r.get("executed_at", "") for r in self.records if r.get("executed_at")]
        return max(stamps) if stamps else self.stamp


def load_runs(results_dir: Path = _RESULTS_DIR) -> list[Run]:
    """Load every run log, oldest-first (filenames sort chronologically)."""
    runs: list[Run] = []
    for path in sorted(glob.glob(str(results_dir / "run-*.jsonl"))):
        p = Path(path)
        records = [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]
        if records:
            stamp = p.stem.replace("run-", "")
            runs.append(Run(path=p, stamp=stamp, records=records))
    return runs


def case_index(cases_dir: Path = _CASES_DIR) -> dict[str, EvalCase]:
    try:
        return {c.case_id: c for c in load_all_cases(cases_dir)}
    except Exception:  # noqa: BLE001 — a dashboard must render even if a case file is mid-edit
        return {}


def _e(text: Any) -> str:
    return html.escape(str(text), quote=True)


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #

_CSS = """
:root {
  --bg:#0a0d14; --panel:#111624; --panel-2:#0d111c; --line:#1f2637;
  --text:#dde3ee; --muted:#7d879b; --faint:#525c72;
  --ok:#3fb950; --bad:#ff5f56; --warn:#d6a020; --err:#f0883e;
  --judge:#4a8fff; --surprise:#e3b341; --accent:#8b9dff;
}
* { box-sizing:border-box; }
body {
  margin:0; background:var(--bg); color:var(--text);
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  font-size:14px; line-height:1.5; -webkit-font-smoothing:antialiased;
}
.mono { font-family:ui-monospace,"Cascadia Code",Menlo,Consolas,monospace; }
a { color:var(--accent); text-decoration:none; }
.wrap { max-width:1180px; margin:0 auto; padding:32px 24px 80px; }

header.top { display:flex; flex-wrap:wrap; align-items:baseline; gap:12px 20px; padding-bottom:20px; border-bottom:1px solid var(--line); }
header.top h1 { margin:0; font-size:22px; letter-spacing:.3px; }
header.top h1 b { color:var(--accent); font-weight:700; }
header.top .sub { color:var(--muted); font-size:13px; }
.meta { margin-left:auto; text-align:right; color:var(--muted); font-size:12.5px; line-height:1.7; }
.meta code { color:var(--text); }

.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin:24px 0 8px; }
.tile { background:linear-gradient(180deg,var(--panel),var(--panel-2)); border:1px solid var(--line); border-radius:12px; padding:16px 18px; position:relative; overflow:hidden; }
.tile .n { font-size:30px; font-weight:700; letter-spacing:-.5px; }
.tile .l { color:var(--muted); font-size:11.5px; text-transform:uppercase; letter-spacing:.9px; margin-top:2px; }
.tile.bad .n{color:var(--bad);} .tile.ok .n{color:var(--ok);} .tile.warn .n{color:var(--surprise);} .tile.err .n{color:var(--err);}
.tile::after { content:""; position:absolute; inset:0 auto 0 0; width:3px; background:var(--line); }
.tile.bad::after{background:var(--bad);} .tile.ok::after{background:var(--ok);} .tile.warn::after{background:var(--surprise);}

h2.sec { font-size:12.5px; text-transform:uppercase; letter-spacing:1.2px; color:var(--muted); margin:36px 0 14px; font-weight:600; }

.cats { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:12px; }
.cat { background:var(--panel); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
.cat .name { font-weight:600; font-size:13px; }
.cat .bar { display:flex; height:8px; border-radius:5px; overflow:hidden; margin:10px 0 8px; background:var(--panel-2); }
.cat .bar span { display:block; }
.cat .bar .pass{background:var(--ok);} .cat .bar .fail{background:var(--bad);} .cat .bar .partial{background:var(--warn);} .cat .bar .error{background:var(--err);}
.cat .legend { color:var(--muted); font-size:12px; }

table.results { width:100%; border-collapse:collapse; margin-top:6px; }
table.results th { text-align:left; font-size:11px; text-transform:uppercase; letter-spacing:.8px; color:var(--faint); font-weight:600; padding:8px 10px; border-bottom:1px solid var(--line); }
table.results td { padding:11px 10px; border-bottom:1px solid var(--line); vertical-align:middle; }
tr.case { cursor:pointer; }
tr.case:hover { background:#0e1320; }
tr.case td:first-child { font-weight:600; }
.chip { display:inline-block; padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; letter-spacing:.3px; border:1px solid transparent; white-space:nowrap; }
.chip.ok{color:var(--ok);border-color:#1c3a24;background:#0e1c12;}
.chip.bad{color:var(--bad);border-color:#4a1f1d;background:#1e0f0e;}
.chip.warn{color:var(--warn);border-color:#3d3011;background:#1c1707;}
.chip.err{color:var(--err);border-color:#402812;background:#1d1208;}
.chip.judge{color:var(--judge);border-color:#173259;background:#0c1526;}
.chip.sev-critical{color:var(--bad);} .chip.sev-high{color:var(--err);} .chip.sev-medium{color:var(--warn);} .chip.sev-low{color:var(--ok);} .chip.sev-info{color:var(--judge);}
.chip.type{color:var(--muted);border-color:var(--line);background:var(--panel-2);}
.surprise-row td { background:#1a1405 !important; }
.badge-surprise { color:var(--surprise); font-weight:700; }
.exp { font-family:ui-monospace,Menlo,Consolas,monospace; color:var(--muted); font-size:12px; }
td.cost { text-align:right; color:var(--muted); }
td.arrow { color:var(--faint); width:18px; }

tr.detail { display:none; }
tr.detail.open { display:table-row; }
tr.detail > td { background:var(--panel-2); padding:0; }
.detail-inner { padding:16px 18px 20px; border-left:2px solid var(--accent); }
.detail-inner .inv { color:var(--text); margin:0 0 4px; }
.detail-inner .inv b { color:var(--accent); }
.detail-inner .desc { color:var(--muted); font-size:12.5px; margin:6px 0 14px; }
.step { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:12px 14px; margin-top:10px; }
.step .head { display:flex; flex-wrap:wrap; gap:10px; align-items:center; color:var(--muted); font-size:12px; margin-bottom:8px; }
.step .head .sid { color:var(--text); font-weight:600; }
.step pre { margin:0; white-space:pre-wrap; word-break:break-word; background:var(--panel-2); border:1px solid var(--line); border-radius:6px; padding:10px 12px; font-size:12.5px; color:#c7cede; max-height:340px; overflow:auto; }
.owasp { color:var(--faint); font-size:11.5px; margin-top:10px; }
.verdict { background:#0c1526; border:1px solid #173259; border-radius:8px; padding:10px 14px; margin:4px 0 6px; font-size:12.5px; }
.verdict .jrat { margin:8px 0 0; color:#c7cede; white-space:pre-wrap; }

table.runs { width:100%; border-collapse:collapse; }
table.runs th,table.runs td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); font-size:12.5px; }
table.runs th { color:var(--faint); font-size:11px; text-transform:uppercase; letter-spacing:.7px; }
table.runs td.num { text-align:right; }
footer { color:var(--faint); font-size:11.5px; margin-top:40px; border-top:1px solid var(--line); padding-top:16px; }
.dot { display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:6px; vertical-align:middle; }
"""

_JS = """
document.querySelectorAll('tr.case').forEach(function(row){
  row.addEventListener('click', function(){
    var d = document.getElementById('detail-' + row.dataset.cid);
    if (d) d.classList.toggle('open');
    var a = row.querySelector('.arrow'); if (a) a.textContent = d && d.classList.contains('open') ? '\\u25be' : '\\u25b8';
  });
});
"""


def _tile(n: Any, label: str, cls: str = "") -> str:
    return f'<div class="tile {cls}"><div class="n">{_e(n)}</div><div class="l">{_e(label)}</div></div>'


def _result_chip(result: str) -> str:
    cls = _RESULT_COLORS.get(result, "type")
    label = {"fail": "EXPLOIT", "pass": "held", "partial": "partial", "error": "error"}.get(result, result)
    return f'<span class="chip {cls}">{_e(label)}</span>'


def _category_breakdown(run: Run) -> str:
    by_cat: dict[str, dict[str, int]] = {}
    for r in run.records:
        c = by_cat.setdefault(r["category"], {"pass": 0, "fail": 0, "partial": 0, "error": 0})
        c[r["result"]] = c.get(r["result"], 0) + 1
    cards = []
    for cat in sorted(by_cat):
        c = by_cat[cat]
        total = sum(c.values()) or 1
        bars = "".join(
            f'<span class="{k}" style="width:{c[k] / total * 100:.1f}%"></span>'
            for k in ("pass", "fail", "partial", "error") if c[k]
        )
        legend = " · ".join(f"{v} {k}" for k, v in c.items() if v)
        cards.append(
            f'<div class="cat"><div class="name">{_e(cat)}</div>'
            f'<div class="bar">{bars}</div><div class="legend">{_e(legend)}</div></div>'
        )
    return f'<div class="cats">{"".join(cards)}</div>'


def _step_block(step: dict[str, Any]) -> str:
    matched = step.get("detector_matched")
    det = "no detector (setup)" if matched is None and not step.get("error") else (
        f"detector {'matched' if matched else 'no match'}" if matched is not None else "—"
    )
    err = step.get("error")
    body = f'<pre>{_e(err)}</pre>' if err else f'<pre>{_e(step.get("observed_behavior") or "(empty)")}</pre>'
    pid = step.get("patient_id", "")
    return (
        '<div class="step"><div class="head">'
        f'<span class="sid">{_e(step["step_id"])}</span>'
        f'<span class="mono">patient {_e(pid[:8])}…</span>'
        f'<span>· {_e(det)}</span>'
        f'<span>· {_result_chip(step["result"]) if step["result"] in _RESULT_COLORS else _e(step["result"])}</span>'
        f'</div>{body}</div>'
    )


def _results_table(run: Run, cases: dict[str, EvalCase]) -> str:
    rows = []
    ordered = sorted(
        run.records,
        key=lambda r: (
            0 if r.get("surprise") else 1,
            0 if r["result"] == "fail" else 1,
            _SEVERITY_ORDER.get((cases.get(r["case_id"]).severity if cases.get(r["case_id"]) else "info"), 5),
        ),
    )
    for r in ordered:
        case = cases.get(r["case_id"])
        cid = _e(r["case_id"])
        sev = case.severity if case else "info"
        ttype = case.test_type if case else "—"
        authority = r.get("authority")
        if authority == "judge_pending":
            judge = '<span class="chip judge">judge-pending</span>'
        elif authority == "judge" and r.get("verdict"):
            judge = f'<span class="chip judge">judged {r["verdict"]["confidence"]:.2f}</span>'
        else:
            judge = ""
        surprise = '<span class="badge-surprise">‼ surprise</span>' if r.get("surprise") else ""
        exp = _e(r["expected_result"])
        row_cls = "case surprise-row" if r.get("surprise") else "case"
        rows.append(
            f'<tr class="{row_cls}" data-cid="{cid}">'
            f'<td>{cid}</td>'
            f'<td>{_e(r["category"])}</td>'
            f'<td><span class="chip type">{_e(ttype)}</span></td>'
            f'<td><span class="chip sev-{_e(sev)}">{_e(sev)}</span></td>'
            f'<td>{_result_chip(r["result"])} {judge}</td>'
            f'<td class="exp">exp {exp}</td>'
            f'<td>{surprise}</td>'
            f'<td class="cost mono">${r["cost"]["usd"]:.4f}</td>'
            f'<td class="arrow">▸</td>'
            "</tr>"
        )
        # detail row
        inv = _e(case.invariant.strip()) if case else "(case definition not found)"
        desc = _e(case.description.strip()) if case else ""
        owasp = " · ".join(_e(o) for o in (case.owasp_refs if case else ()))
        steps_html = "".join(_step_block(s) for s in r["steps"])
        verdict_html = ""
        v = r.get("verdict")
        if v:
            esc = " · escalated to human" if v.get("escalate_to_human") else ""
            verdict_html = (
                '<div class="verdict"><b>Judge verdict:</b> '
                f'{_result_chip(v["result"])} conf {v["confidence"]:.2f} · '
                f'{_e(v.get("rubric_id", ""))} v{_e(v.get("rubric_version", ""))}{esc}'
                f'<p class="jrat">{_e(v.get("rationale", ""))}</p></div>'
            )
        rows.append(
            f'<tr class="detail" id="detail-{cid}"><td colspan="9"><div class="detail-inner">'
            f'<p class="inv"><b>Invariant:</b> {inv}</p>'
            f'<p class="desc">{desc}</p>'
            f'{verdict_html}'
            f'{steps_html}'
            f'<div class="owasp">OWASP: {owasp}</div>'
            "</div></td></tr>"
        )
    return (
        '<table class="results"><thead><tr>'
        "<th>case</th><th>category</th><th>type</th><th>severity</th><th>result</th>"
        "<th>expected</th><th></th><th>cost</th><th></th>"
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
    )


def _run_history(runs: list[Run]) -> str:
    rows = []
    for run in reversed(runs):  # newest first
        rows.append(
            "<tr>"
            f'<td class="mono">{_e(run.executed_at)}</td>'
            f'<td class="mono">{_e(run.target_version)}</td>'
            f'<td class="num">{len(run.records)}</td>'
            f'<td class="num" style="color:var(--bad)">{run.exploits}</td>'
            f'<td class="num" style="color:var(--surprise)">{run.surprises}</td>'
            f'<td class="num">{run.errors}</td>'
            f'<td class="num mono">${run.usd:.4f}</td>'
            "</tr>"
        )
    return (
        '<table class="runs"><thead><tr>'
        "<th>run</th><th>target ver</th><th class='num'>cases</th><th class='num'>exploits</th>"
        "<th class='num'>surprises</th><th class='num'>errors</th><th class='num'>cost</th>"
        f'</tr></thead><tbody>{"".join(rows)}</tbody></table>'
    )


def render(runs: list[Run], cases: dict[str, EvalCase]) -> str:
    latest = runs[-1]
    categories = sorted({r["category"] for r in latest.records})
    tiles = "".join([
        _tile(len(latest.records), "cases run"),
        _tile(latest.exploits, "exploits confirmed", "bad" if latest.exploits else "ok"),
        _tile(latest.surprises, "surprises", "warn" if latest.surprises else ""),
        _tile(len(categories), "categories"),
        _tile(f"${latest.usd:.4f}", "run cost"),
        _tile(f"{latest.tokens:,}", "tokens"),
    ])
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentForge — Eval Dashboard</title>
<style>{_CSS}</style></head>
<body><div class="wrap">
<header class="top">
  <h1><b>AgentForge</b> · Eval Dashboard</h1>
  <span class="sub">adversarial evaluation of the Clinical Co-Pilot</span>
  <div class="meta">
    target <code>{_e(TARGET_BASE_URL)}</code><br>
    version <code>{_e(latest.target_version)}</code> · run <code>{_e(latest.executed_at)}</code>
  </div>
</header>

<div class="tiles">{tiles}</div>

<h2 class="sec">Results by category</h2>
{_category_breakdown(latest)}

<h2 class="sec">Latest run · {_e(len(latest.records))} cases <span style="color:var(--faint);text-transform:none;letter-spacing:0"> — click a row for the transcript</span></h2>
{_results_table(latest, cases)}

<h2 class="sec">Run history</h2>
{_run_history(runs)}

<footer>
  <span class="dot" style="background:var(--bad)"></span>EXPLOIT = target failed to stay secure ·
  <span class="dot" style="background:var(--ok)"></span>held = defense held ·
  <span class="dot" style="background:var(--surprise)"></span>surprise = result contradicts expectation (authoritative detector only) ·
  <span class="dot" style="background:var(--judge)"></span>judge-pending = coarse detector, Phase 4 Judge finalizes.<br>
  Generated locally from evals/results/ — contains demo PHI, not for publication.
</footer>
</div>
<script>{_JS}</script>
</body></html>"""


def build(out_path: Path, *, results_dir: Path = _RESULTS_DIR, cases_dir: Path = _CASES_DIR) -> Path:
    runs = load_runs(results_dir)
    if not runs:
        raise SystemExit(
            f"no run logs found in {results_dir}. Run `python -m evals.run` first to produce results."
        )
    html_text = render(runs, case_index(cases_dir))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html_text, encoding="utf-8")
    return out_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.dashboard", description="Render the eval dashboard HTML")
    parser.add_argument("--out", type=Path, default=_RESULTS_DIR / "dashboard.html")
    parser.add_argument("--results-dir", type=Path, default=_RESULTS_DIR)
    parser.add_argument("--open", dest="open_browser", action="store_true", help="open the dashboard after building")
    args = parser.parse_args(argv)

    out = build(args.out, results_dir=args.results_dir)
    runs = load_runs(args.results_dir)
    print(f"dashboard written to {out}  ({len(runs)} run(s), latest {runs[-1].executed_at})")
    if args.open_browser:
        webbrowser.open(out.resolve().as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
