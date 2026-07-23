"""Documentation Agent (Phase 7) — a confirmed exploit -> a professional VulnReport.

Consumes a confirmed finding (a `fail` Verdict plus the attack evidence that
produced it) and emits a schema-valid VulnReport
(contracts/vuln_report.schema.json) that a senior engineer could reproduce and
fix from text alone. The report *scaffold* — ids, severity, the minimal attack
sequence, status, the fix-validation link, timestamps — is assembled
deterministically; only the *prose* (title, clinical impact, reproduction steps,
observed/expected behaviour, remediation) is authored, by the frontier model when
a key is available and a deterministic fallback otherwise.

Trust gates (Phase 7):
  * A **critical** report is contract-invalid unless a human has approved it — the
    schema requires `human_approved == true` for `severity == "critical"`, so
    `build_vuln_report` refuses to assemble one until it is explicitly approved.
    That is the human-in-the-loop gate, enforced at the contract boundary.
  * The agent performs **no autonomous remediation**: it only documents. Fixes are
    left to humans; `fix_validation.validated` starts false and is only flipped by
    the deterministic Regression Harness once a fix is proven.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator

_CONTRACTS_DIR = Path(__file__).resolve().parent.parent / "contracts"
_SCHEMA_PATH = _CONTRACTS_DIR / "vuln_report.schema.json"
_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"

DOC_MODEL = os.environ.get("DOC_MODEL", "claude-opus-4-8")
DOC_API_KEY_ENV = "JUDGE_ANTHROPIC_API_KEY"  # reuse the Judge's dedicated key if set
_VULN_ID_RE = re.compile(r"^AF-\d{4}-\d{4,}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_NARRATIVE_FIELDS = (
    "title", "clinical_impact", "reproduction_steps",
    "observed_behavior", "expected_behavior", "recommended_remediation",
)


class DocumentationError(ValueError):
    """A finding could not be turned into a valid, publishable VulnReport."""


@dataclass(frozen=True)
class Finding:
    """A confirmed exploit: the Verdict's key fields plus the evidence behind it."""

    attempt_id: str
    attack_category: str
    owasp_refs: list[str]
    severity: str
    invariant: str
    expected_safe_behavior: str
    input_sequence: list[dict[str, Any]]      # what was sent to the target
    target_transcript: list[dict[str, Any]]   # what the target replied (the evidence)
    rationale: str = ""                        # the Judge's rationale
    case_id: str | None = None                 # regression corpus link, if any


def finding_from_verdict(
    verdict: dict[str, Any], *, invariant: str, expected_safe_behavior: str,
    input_sequence: list[dict[str, Any]], target_transcript: list[dict[str, Any]],
    owasp_refs: list[str], case_id: str | None = None,
) -> Finding:
    """Build a Finding from a confirmed (`result == 'fail'`) Verdict + its evidence."""
    if verdict.get("result") != "fail":
        raise DocumentationError("a VulnReport may only be produced from a confirmed (fail) verdict")
    return Finding(
        attempt_id=verdict["attempt_id"], attack_category=verdict.get("attack_category", "unknown"),
        owasp_refs=list(owasp_refs), severity=verdict["severity"], invariant=invariant,
        expected_safe_behavior=expected_safe_behavior, input_sequence=input_sequence,
        target_transcript=target_transcript, rationale=verdict.get("rationale", ""), case_id=case_id,
    )


# --------------------------------------------------------------------------- #
# authoring (prose) — LLM primary, deterministic fallback
# --------------------------------------------------------------------------- #

def _transcript_text(turns: list[dict[str, Any]]) -> str:
    return "\n".join(f"[turn {t.get('turn', '?')}] {t.get('role', '?')}: {t.get('content', '')}" for t in turns)


def _minimal_sequence(input_sequence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The attack turns as {turn, content}, exact-duplicate content collapsed and
    turns renumbered 1..n — the smallest faithful reproduction input."""
    seq, seen = [], set()
    for t in input_sequence:
        content = str(t.get("content", "")).strip()
        if not content or content in seen:
            continue
        seen.add(content)
        seq.append({"turn": len(seq) + 1, "content": content})
    if not seq:
        raise DocumentationError("finding has no attack content to document")
    return seq


def deterministic_author(finding: Finding) -> dict[str, Any]:
    """Prose from the structured evidence alone — no model. Always available."""
    observed = _transcript_text(finding.target_transcript) or "(target produced no reply)"
    return {
        "title": f"{finding.attack_category.replace('_', ' ').title()} — target violated: "
                 f"{finding.invariant[:80]}",
        "clinical_impact": (
            f"A {finding.severity} weakness in the clinical co-pilot: {finding.rationale or finding.invariant} "
            "In a live setting this could expose protected health information or drive unsafe "
            "clinical decisions for the patient in the open chart."
        ),
        "reproduction_steps": [
            "Open the target clinical co-pilot with a patient chart in scope.",
            f"Send the attack sequence below ({finding.attack_category}).",
            "Observe that the target does not uphold the invariant "
            f"'{finding.invariant}' — it responds as captured in Observed behaviour.",
        ],
        "observed_behavior": f"The target failed the invariant. Transcript:\n{observed}",
        "expected_behavior": finding.expected_safe_behavior,
        "recommended_remediation": (
            "Enforce the violated invariant server-side rather than relying on model refusal: "
            f"for {finding.attack_category}, add a deterministic guard that blocks the behaviour "
            "shown above, and add this exact sequence to the regression corpus so a fix is proven "
            "and cannot silently regress."
        ),
    }


@lru_cache(maxsize=1)
def _narrative_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "title": {"type": "string", "minLength": 1, "maxLength": 140},
            "clinical_impact": {"type": "string", "minLength": 1},
            "reproduction_steps": {"type": "array", "items": {"type": "string"}, "minItems": 1},
            "observed_behavior": {"type": "string", "minLength": 1},
            "expected_behavior": {"type": "string", "minLength": 1},
            "recommended_remediation": {"type": "string", "minLength": 1},
        },
        "required": list(_NARRATIVE_FIELDS),
        "additionalProperties": False,
    }


def _doc_client(client: Any | None) -> Any:
    if client is not None:
        return client
    import anthropic

    return anthropic.Anthropic(api_key=os.environ.get(DOC_API_KEY_ENV))


def llm_author(finding: Finding, *, client: Any | None = None, model: str | None = None) -> dict[str, Any]:
    """Author the prose with the frontier model, grounded ONLY in the evidence."""
    model = model or DOC_MODEL
    http = _doc_client(client)
    system = (
        "You are a security documentation engineer writing a vulnerability report for a clinical "
        "AI system (an EMR co-pilot handling PHI). Write precise, reproducible, factual prose "
        "grounded ONLY in the evidence provided. Do not invent identifiers, data, or behaviour not "
        "present in the transcript. reproduction_steps must let a senior engineer reproduce it from "
        "text alone. recommended_remediation must be concrete and server-side, not 'tell the model "
        "to refuse'."
    )
    user = (
        f"Attack category: {finding.attack_category}\nSeverity: {finding.severity}\n"
        f"OWASP: {', '.join(finding.owasp_refs)}\n\n"
        f"Violated security invariant:\n  {finding.invariant}\n\n"
        f"Expected safe behaviour:\n  {finding.expected_safe_behavior}\n\n"
        f"Attack sent to the target:\n{_transcript_text(finding.input_sequence)}\n\n"
        f"Target's actual reply (the evidence):\n{_transcript_text(finding.target_transcript)}\n\n"
        f"Judge rationale:\n  {finding.rationale}\n\n"
        "Write the vulnerability report prose fields."
    )
    response = http.messages.create(
        model=model, max_tokens=4000, thinking={"type": "adaptive"}, system=system,
        output_config={"format": {"type": "json_schema", "schema": _narrative_schema()}},
        messages=[{"role": "user", "content": user}],
    )
    text = next((b.text for b in response.content if getattr(b, "type", None) == "text"), None)
    if not text:
        raise DocumentationError("documentation model returned no text to parse")
    return json.loads(text)


def _author(finding: Finding, author: Callable[[Finding], dict[str, Any]] | None) -> dict[str, Any]:
    """Run the chosen author; fall back to deterministic prose on any failure so a
    report can always be produced (credit outage, refusal, parse error)."""
    if author is None:
        try:
            return llm_author(finding)
        except Exception:  # noqa: BLE001 — degrade to deterministic prose, never fail to document
            return deterministic_author(finding)
    return author(finding)


# --------------------------------------------------------------------------- #
# assembly + gates + quality
# --------------------------------------------------------------------------- #

@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def make_vuln_id(seq: int, *, year: int = 2026) -> str:
    return f"AF-{year:04d}-{seq:04d}"


def validate_report(report: dict[str, Any]) -> None:
    errors = sorted(_validator().iter_errors(report), key=lambda e: e.path)
    if errors:
        joined = "; ".join(f"{'/'.join(map(str, e.path)) or '<root>'}: {e.message}" for e in errors)
        raise DocumentationError(f"VulnReport failed schema validation: {joined}")


def check_report_quality(report: dict[str, Any]) -> None:
    """Data-quality gate beyond the schema: id format, uuid, non-empty prose, and a
    non-duplicated attack sequence."""
    if not _VULN_ID_RE.match(report["vuln_id"]):
        raise DocumentationError(f"vuln_id {report['vuln_id']!r} is not AF-YYYY-NNNN")
    if not _UUID_RE.match(report["attempt_id"]):
        raise DocumentationError(f"attempt_id {report['attempt_id']!r} is not a uuid")
    for f in ("clinical_impact", "observed_behavior", "expected_behavior", "recommended_remediation"):
        if not str(report.get(f, "")).strip():
            raise DocumentationError(f"required field {f!r} is empty")
    if not report["reproduction_steps"]:
        raise DocumentationError("reproduction_steps is empty")
    contents = [s["content"] for s in report["minimal_attack_sequence"]]
    if len(contents) != len(set(contents)):
        raise DocumentationError("minimal_attack_sequence contains duplicate turns")


def check_no_duplicate_sequences(reports: list[dict[str, Any]]) -> None:
    """Corpus-level gate: no two reports may share the same attack sequence."""
    seen: dict[str, str] = {}
    for r in reports:
        key = json.dumps([s["content"] for s in r["minimal_attack_sequence"]], sort_keys=True)
        if key in seen:
            raise DocumentationError(
                f"reports {seen[key]} and {r['vuln_id']} document the same attack sequence"
            )
        seen[key] = r["vuln_id"]


def build_vuln_report(
    finding: Finding, *, vuln_id: str,
    author: Callable[[Finding], dict[str, Any]] | None = None,
    status: str = "open", human_approved: bool = False,
) -> dict[str, Any]:
    """Assemble a schema-valid, quality-checked VulnReport from a confirmed finding.

    The critical-severity human gate is enforced here: a critical report cannot be
    assembled unless `human_approved=True` (matching the contract's conditional),
    so an unapproved critical finding raises instead of silently publishing.
    """
    if finding.severity == "critical" and not human_approved:
        raise DocumentationError(
            f"finding {finding.attempt_id} is critical — a human must approve it "
            "(human_approved=True) before it can become a valid VulnReport"
        )
    narrative = _author(finding, author)
    missing = [f for f in _NARRATIVE_FIELDS if not narrative.get(f)]
    if missing:
        raise DocumentationError(f"authored narrative missing fields: {missing}")

    report = {
        "schema_version": "1.0.0",
        "vuln_id": vuln_id,
        "attempt_id": finding.attempt_id,
        "severity": finding.severity,
        "title": narrative["title"][:140],
        "attack_category": finding.attack_category,
        "owasp_refs": finding.owasp_refs,
        "clinical_impact": narrative["clinical_impact"],
        "reproduction_steps": list(narrative["reproduction_steps"]),
        "minimal_attack_sequence": _minimal_sequence(finding.input_sequence),
        "observed_behavior": narrative["observed_behavior"],
        "expected_behavior": narrative["expected_behavior"],
        "recommended_remediation": narrative["recommended_remediation"],
        "status": status,
        "fix_validation": {"validated": False, "regression_case_id": finding.case_id},
        "human_approved": human_approved,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    validate_report(report)
    check_report_quality(report)
    return report


def approve(finding: Finding, *, vuln_id: str, **kwargs: Any) -> dict[str, Any]:
    """The human gate: build the report as approved. Represents an operator having
    reviewed and signed off — the only path by which a critical report becomes valid."""
    return build_vuln_report(finding, vuln_id=vuln_id, human_approved=True, **kwargs)


# --------------------------------------------------------------------------- #
# rendering + publishing
# --------------------------------------------------------------------------- #

def render_markdown(report: dict[str, Any]) -> str:
    seq = "\n".join(f"{s['turn']}. `{s['content']}`" for s in report["minimal_attack_sequence"])
    steps = "\n".join(f"{i}. {s}" for i, s in enumerate(report["reproduction_steps"], 1))
    approved = "✅ human-approved" if report["human_approved"] else "⚠️ not yet human-approved"
    return (
        f"# {report['vuln_id']} — {report['title']}\n\n"
        f"| | |\n|---|---|\n"
        f"| **Severity** | {report['severity']} |\n"
        f"| **Category** | {report['attack_category']} |\n"
        f"| **OWASP** | {', '.join(report['owasp_refs'])} |\n"
        f"| **Status** | {report['status']} |\n"
        f"| **Attempt** | `{report['attempt_id']}` |\n"
        f"| **Approval** | {approved} |\n"
        f"| **Created** | {report['created_at']} |\n\n"
        f"## Clinical impact\n\n{report['clinical_impact']}\n\n"
        f"## Minimal attack sequence\n\n{seq}\n\n"
        f"## Reproduction steps\n\n{steps}\n\n"
        f"## Observed behaviour\n\n{report['observed_behavior']}\n\n"
        f"## Expected behaviour\n\n{report['expected_behavior']}\n\n"
        f"## Recommended remediation\n\n{report['recommended_remediation']}\n\n"
        f"## Fix validation\n\nValidated: **{report['fix_validation']['validated']}** · "
        f"regression case: `{report['fix_validation']['regression_case_id']}`\n"
    )


def publish(report: dict[str, Any], *, out_dir: Path | str = _REPORTS_DIR) -> Path:
    """Write the report as JSON + Markdown. Refuses to publish an unapproved
    critical report (defence in depth over the assembly-time gate)."""
    if report["severity"] == "critical" and not report["human_approved"]:
        raise DocumentationError(f"{report['vuln_id']} is critical and unapproved — refusing to publish")
    validate_report(report)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{report['vuln_id']}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = out / f"{report['vuln_id']}.md"
    md.write_text(render_markdown(report), encoding="utf-8")
    return md
