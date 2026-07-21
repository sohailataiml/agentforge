"""Load, validate, and reason about eval cases (evals/cases/**/*.yaml).

An eval case is the reproducible unit of the attack suite: a security invariant
(or boundary, or regression guard) plus the exact input sequence that probes it
and a deterministic detector that decides whether the target held or failed.
Cases are authored as YAML and validated against
contracts/eval_case.schema.json before anything is sent to the target, so a
malformed case fails fast at load time, never mid-campaign.

Nothing here touches the network — this module is the pure, testable core that
the runner (agentforge.eval_runner) executes against the live target.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from jsonschema import Draft202012Validator

_CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"
_CASE_SCHEMA_PATH = _CONTRACTS_DIR / "eval_case.schema.json"

DetectorSignal = Literal["exploit", "safe"]
DetectorKind = Literal["contains_any", "contains_all", "regex"]
StepResult = Literal["pass", "fail", "partial", "error", "setup"]


class EvalCaseError(ValueError):
    """A case file was missing, unparseable, or failed schema validation."""


@lru_cache(maxsize=1)
def _case_validator() -> Draft202012Validator:
    schema = json.loads(_CASE_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


@dataclass(frozen=True)
class Detector:
    """Deterministic pass/fail signal over a step's assistant transcript."""

    signals: DetectorSignal
    kind: DetectorKind
    patterns: tuple[str, ...]
    ignore_case: bool = True

    def matched(self, transcript_text: str) -> bool:
        """Whether the raw detector condition fires against the transcript.

        This is the literal 'did the pattern hit', independent of polarity —
        `signals` is applied by `outcome` to translate a match into pass/fail.
        """
        haystack = transcript_text.lower() if self.ignore_case else transcript_text
        if self.kind == "regex":
            flags = re.IGNORECASE if self.ignore_case else 0
            return re.search(self.patterns[0], transcript_text, flags) is not None
        needles = [p.lower() if self.ignore_case else p for p in self.patterns]
        if self.kind == "contains_all":
            return all(n in haystack for n in needles)
        return any(n in haystack for n in needles)  # contains_any

    def outcome(self, transcript_text: str) -> StepResult:
        """Translate a match into a security verdict via `signals` polarity.

        signals='exploit': a match means the exploit landed → 'fail'.
        signals='safe':    a match means the defense held  → 'pass'.
        """
        hit = self.matched(transcript_text)
        if self.signals == "exploit":
            return "fail" if hit else "pass"
        return "pass" if hit else "fail"

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Detector:
        return Detector(
            signals=data["signals"],
            kind=data["kind"],
            patterns=tuple(data["patterns"]),
            ignore_case=data.get("ignore_case", True),
        )


@dataclass(frozen=True)
class Step:
    """One send_to_target call within a case."""

    step_id: str
    patient_id: str
    session: str  # "new" | "reuse:<step_id>"
    input_sequence: tuple[dict[str, Any], ...]
    detector: Detector | None = None

    @property
    def reuse_of(self) -> str | None:
        """The step_id whose session this step continues, or None for 'new'."""
        if self.session.startswith("reuse:"):
            return self.session.split(":", 1)[1]
        return None

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Step:
        detector = data.get("detector")
        return Step(
            step_id=data["step_id"],
            patient_id=data["patient_id"],
            session=data["session"],
            input_sequence=tuple(data["input_sequence"]),
            detector=Detector.from_dict(detector) if detector else None,
        )


@dataclass(frozen=True)
class EvalCase:
    """A fully-validated eval case ready to execute against the target."""

    case_id: str
    category: str
    subcategory: str
    owasp_refs: tuple[str, ...]
    description: str
    test_type: Literal["boundary", "invariant", "regression"]
    invariant: str
    expected_safe_behavior: str
    severity: str
    exploitability: str
    add_to_regression: bool
    expected_result: Literal["pass", "fail", "partial"]
    steps: tuple[Step, ...]
    requires_judge: bool = False
    source_path: Path | None = field(default=None, compare=False)

    @staticmethod
    def from_dict(data: dict[str, Any], *, source_path: Path | None = None) -> EvalCase:
        return EvalCase(
            case_id=data["case_id"],
            category=data["category"],
            subcategory=data["subcategory"],
            owasp_refs=tuple(data["owasp_refs"]),
            description=data["description"],
            test_type=data["test_type"],
            invariant=data["invariant"],
            expected_safe_behavior=data["expected_safe_behavior"],
            severity=data["severity"],
            exploitability=data["exploitability"],
            add_to_regression=data["add_to_regression"],
            expected_result=data["expected_result"],
            steps=tuple(Step.from_dict(s) for s in data["steps"]),
            requires_judge=data.get("requires_judge", False),
            source_path=source_path,
        )


def _validate(raw: dict[str, Any], *, where: str) -> None:
    errors = sorted(_case_validator().iter_errors(raw), key=lambda e: e.path)
    if errors:
        joined = "; ".join(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
        raise EvalCaseError(f"{where}: schema validation failed: {joined}")


def _validate_step_references(case: EvalCase, *, where: str) -> None:
    """A 'reuse:<step_id>' must point at an earlier step in the same case."""
    seen: set[str] = set()
    for step in case.steps:
        ref = step.reuse_of
        if ref is not None and ref not in seen:
            raise EvalCaseError(
                f"{where}: step '{step.step_id}' reuses session of "
                f"'{ref}', which is not an earlier step in this case"
            )
        seen.add(step.step_id)


def load_case(path: str | Path) -> EvalCase:
    """Load and fully validate a single YAML case file."""
    path = Path(path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise EvalCaseError(f"{path}: could not read/parse YAML: {exc}") from exc
    if not isinstance(raw, dict):
        raise EvalCaseError(f"{path}: top-level YAML must be a mapping, got {type(raw).__name__}")
    _validate(raw, where=str(path))
    case = EvalCase.from_dict(raw, source_path=path)
    _validate_step_references(case, where=str(path))
    return case


def load_all_cases(cases_dir: str | Path) -> list[EvalCase]:
    """Load every *.yaml case under cases_dir, sorted by path for stable order.

    Raises on the first malformed case and on any duplicate case_id — a reused
    id would silently overwrite a regression key, so it is a hard error.
    """
    cases_dir = Path(cases_dir)
    files = sorted(cases_dir.rglob("*.yaml")) + sorted(cases_dir.rglob("*.yml"))
    cases: list[EvalCase] = []
    seen: dict[str, Path] = {}
    for f in sorted(set(files)):
        case = load_case(f)
        if case.case_id in seen:
            raise EvalCaseError(
                f"duplicate case_id '{case.case_id}' in {f} and {seen[case.case_id]}"
            )
        seen[case.case_id] = f
        cases.append(case)
    return cases
