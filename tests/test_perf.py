"""Smoke tests for the perf harness (Phase 8).

Keep the offline benches runnable and honest — small sizes so the suite stays fast,
asserting the shape and sane bounds of each measurement (not absolute timings, which
are machine-dependent). The live latency sampler is not exercised here.
"""

from __future__ import annotations

from agentforge.perf import bench_detector, bench_framework, bench_observability, bench_regression


def test_bench_framework_runs_without_network():
    r = bench_framework(n=10)                 # instant mock target, no Judge
    assert r["cases"] == 10 and r["cases_per_s"] > 0 and r["ms_per_case"] >= 0
    assert r["peak_mem_mb"] >= 0


def test_bench_detector_reports_per_op():
    r = bench_detector(iters=1000)
    assert r["iters"] == 1000 and r["us_per_op"] > 0


def test_bench_regression_replays_all():
    r = bench_regression(n=8)
    assert r["exploits"] == 8 and r["replays_per_s"] > 0


def test_bench_observability_scales():
    r = bench_observability(n=500)
    assert r["records"] == 500 and r["wall_ms"] >= 0
