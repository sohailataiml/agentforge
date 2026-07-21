"""Validate Judge accuracy against the labeled ground-truth mini-set.

Runs the Judge over judge/ground_truth.yaml (labeled attempts) and reports how
often the Verdict matches the human label. This is the gate that says the Judge
is trustworthy enough to produce authoritative verdicts before we wire it into
the runner — a Judge that disagrees with clear-cut ground truth would poison
every downstream score.

    python -m agentforge.judge_eval          # run live, print an accuracy report
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from agentforge.judge import JudgeInput, judge_attempt

_GROUND_TRUTH = Path(__file__).resolve().parent.parent / "judge" / "ground_truth.yaml"


@dataclass
class Scored:
    id: str
    category: str
    label: str
    predicted: str
    confidence: float
    correct: bool
    cost_usd: float
    rationale: str


def load_ground_truth(path: Path = _GROUND_TRUTH) -> list[dict[str, Any]]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or not data:
        raise ValueError(f"{path}: expected a non-empty list of labeled entries")
    return data


def _to_input(entry: dict[str, Any]) -> JudgeInput:
    return JudgeInput(
        attack_category=entry["attack_category"],
        invariant=entry["invariant"],
        expected_safe_behavior=entry["expected_safe_behavior"],
        input_sequence=list(entry.get("input_sequence", [])),
        target_transcript=list(entry["target_transcript"]),
    )


def score_all(*, client: Any | None = None, model: str | None = None) -> list[Scored]:
    """Judge every ground-truth entry live and score it against its label."""
    scored: list[Scored] = []
    for entry in load_ground_truth():
        verdict = judge_attempt(_to_input(entry), client=client, model=model)
        predicted = verdict.result
        label = entry["label"]
        scored.append(
            Scored(
                id=entry["id"],
                category=entry["attack_category"],
                label=label,
                predicted=predicted,
                confidence=verdict.verdict["confidence"],
                correct=predicted == label,
                cost_usd=verdict.cost["usd"],
                rationale=verdict.verdict["rationale"],
            )
        )
    return scored


def accuracy(scored: list[Scored]) -> float:
    return sum(s.correct for s in scored) / len(scored) if scored else 0.0


def format_report(scored: list[Scored]) -> str:
    lines = ["=== Judge accuracy vs ground truth ==="]
    width = max((len(s.id) for s in scored), default=0)
    for s in scored:
        mark = "ok " if s.correct else "MISS"
        lines.append(
            f"  [{mark}] {s.id:<{width}}  label={s.label:<7} pred={s.predicted:<7} "
            f"conf={s.confidence:.2f}  ${s.cost_usd:.4f}"
        )
        if not s.correct:
            lines.append(f"         rationale: {s.rationale[:200]}")
    acc = accuracy(scored)
    total_cost = sum(s.cost_usd for s in scored)
    lines.append(f"\n  accuracy: {acc:.0%} ({sum(s.correct for s in scored)}/{len(scored)})")
    lines.append(f"  cost: ${total_cost:.4f}")
    return "\n".join(lines)


def main() -> int:
    scored = score_all()
    print(format_report(scored))
    # Non-zero exit if the Judge falls below a trust bar on clear-cut ground truth.
    return 0 if accuracy(scored) >= 0.9 else 1


if __name__ == "__main__":
    raise SystemExit(main())
