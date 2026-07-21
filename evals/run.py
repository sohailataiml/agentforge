"""CLI entrypoint for the AgentForge attack suite.

    python -m evals.run --list          # load + validate every case, no network
    python -m evals.run --dry-run       # show the execution plan, no network
    python -m evals.run                 # run all cases live, write a JSONL run log
    python -m evals.run --case <id>     # run a single case live
    python -m evals.run --category dos  # run only one category

Live runs hit the real deployed target (paid /chat calls), per the platform's
no-mocks constraint. --list / --dry-run make no network calls, so they are safe
to run in CI and are what the test suite exercises.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from agentforge.eval_case import EvalCase, EvalCaseError, load_all_cases
from agentforge.eval_runner import EvalResult, run_suite, write_results_jsonl

_CASES_DIR = Path(__file__).resolve().parent / "cases"
_RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Exit codes: 0 = clean run; 2 = a run error (target unreachable / bad case);
# 3 = a surprise (a defense expected to hold failed, or a known finding no
# longer reproduces) — CI-meaningful signal distinct from an infra error.
_EXIT_OK = 0
_EXIT_USAGE = 1
_EXIT_RUN_ERROR = 2
_EXIT_SURPRISE = 3


def _load(cases_dir: Path, *, case_id: str | None, category: str | None) -> list[EvalCase]:
    cases = load_all_cases(cases_dir)
    if case_id:
        cases = [c for c in cases if c.case_id == case_id]
        if not cases:
            raise EvalCaseError(f"no case with case_id '{case_id}' under {cases_dir}")
    if category:
        cases = [c for c in cases if c.category == category]
        if not cases:
            raise EvalCaseError(f"no cases in category '{category}' under {cases_dir}")
    return cases


def _print_list(cases: list[EvalCase]) -> None:
    print(f"{len(cases)} case(s) loaded and schema-valid:\n")
    width = max((len(c.case_id) for c in cases), default=0)
    for c in cases:
        judge = " [judge]" if c.requires_judge else ""
        print(
            f"  {c.case_id:<{width}}  {c.category:<18} {c.test_type:<11} "
            f"exp={c.expected_result:<7} sev={c.severity}{judge}"
        )
    categories = sorted({c.category for c in cases})
    print(f"\ncategories covered ({len(categories)}): {', '.join(categories)}")


def _print_plan(cases: list[EvalCase]) -> None:
    for c in cases:
        print(f"\n{c.case_id}  ({c.category} / {c.test_type})")
        print(f"    invariant: {c.invariant.strip()}")
        for s in c.steps:
            det = "no detector (setup)" if s.detector is None else (
                f"detector: {s.detector.signals}/{s.detector.kind}"
            )
            print(f"    step {s.step_id}: patient={s.patient_id[:8]}… session={s.session}  {det}")


def _print_results(results: list[EvalResult]) -> None:
    print("\n=== results ===")
    width = max((len(r.case_id) for r in results), default=0)
    for r in results:
        flag = ""
        if r.result == "error":
            flag = "  !! ERROR"
        elif r.surprise:
            flag = f"  !! SURPRISE (expected {r.expected_result})"
        auth = {"detector": "", "judge": "  (judged)", "judge_pending": "  (judge_pending)"}.get(r.authority, "")
        conf = ""
        if r.verdict is not None:
            conf = f" conf={r.verdict['confidence']:.2f}"
        print(f"  {r.case_id:<{width}}  {r.result:<7} ${r.cost['usd']:.4f}{auth}{conf}{flag}")

    total_usd = sum(r.cost["usd"] for r in results)
    total_tokens = sum(r.cost["tokens"] for r in results)
    n_fail = sum(1 for r in results if r.result == "fail")
    n_error = sum(1 for r in results if r.result == "error")
    n_surprise = sum(1 for r in results if r.surprise)
    print(
        f"\n  {len(results)} case(s): {n_fail} exploit(s) confirmed, "
        f"{n_surprise} surprise(s), {n_error} error(s)"
    )
    print(f"  cost: {total_tokens} tokens, ${total_usd:.4f}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="evals.run", description="AgentForge attack suite runner")
    parser.add_argument("--cases-dir", type=Path, default=_CASES_DIR)
    parser.add_argument("--case", dest="case_id", help="run a single case by case_id")
    parser.add_argument("--category", help="run only cases in this attack category")
    parser.add_argument("--base-url", help="override the target base URL")
    parser.add_argument("--out", type=Path, help="JSONL run-log path (default: evals/results/run-<ts>.jsonl)")
    parser.add_argument("--judge", action="store_true", help="score requires_judge cases with the Phase 4 Judge (Opus 4.8)")
    parser.add_argument("--judge-all", action="store_true", help="score EVERY case with the Judge, not just requires_judge ones")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--list", action="store_true", help="list valid cases, no network")
    mode.add_argument("--dry-run", action="store_true", help="show execution plan, no network")
    args = parser.parse_args(argv)

    # Case text and invariants carry em-dashes and other non-ASCII; force UTF-8
    # so printing a run summary never dies on a legacy Windows console codepage.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8", errors="replace")

    try:
        cases = _load(args.cases_dir, case_id=args.case_id, category=args.category)
    except EvalCaseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    if args.list:
        _print_list(cases)
        return _EXIT_OK
    if args.dry_run:
        _print_plan(cases)
        return _EXIT_OK

    judge_fn = None
    if args.judge or args.judge_all:
        from agentforge.judge import judge_attempt  # lazy: only needs the SDK/key when judging

        judge_fn = judge_attempt
        print("Judge enabled (Opus 4.8) — "
              f"{'every case' if args.judge_all else 'requires_judge cases'} will be scored by the Judge.")

    print(f"running {len(cases)} case(s) live against {args.base_url or 'the deployed target'} …")
    results = run_suite(cases, base_url=args.base_url, judge=judge_fn, judge_all=args.judge_all)
    _print_results(results)

    out = args.out or (_RESULTS_DIR / f"run-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.jsonl")
    write_results_jsonl(results, out)
    print(f"\nrun log written to {out}")

    if any(r.result == "error" for r in results):
        return _EXIT_RUN_ERROR
    if any(r.surprise for r in results):
        return _EXIT_SURPRISE
    return _EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
