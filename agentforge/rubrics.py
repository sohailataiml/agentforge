"""Load the frozen, versioned judging rubrics (rubrics/*.md).

Each rubric is a markdown file with a YAML frontmatter block carrying its
`rubric_id` and `rubric_version`. The Judge composes the shared `_base` rubric
with the per-category rubric so every verdict is scored against a fixed,
inspectable standard — the rubric_id/version end up on the Verdict, so a scoring
change is a visible version bump, not a silent prompt edit.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

_RUBRICS_DIR = Path(__file__).resolve().parent.parent / "rubrics"
_FRONTMATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)

# attack_category values that must each have a rubric (mirrors the contracts enum)
CATEGORIES = (
    "prompt_injection",
    "data_exfiltration",
    "state_corruption",
    "tool_misuse",
    "dos",
    "identity_role",
)


class RubricError(ValueError):
    """A rubric file is missing or malformed."""


@dataclass(frozen=True)
class Rubric:
    rubric_id: str
    rubric_version: str
    body: str

    def compose(self, base: Rubric) -> str:
        """Full judging instruction = shared base rubric + this category rubric."""
        return f"{base.body.strip()}\n\n---\n\n{self.body.strip()}"


def _parse(path: Path) -> Rubric:
    if not path.is_file():
        raise RubricError(f"rubric not found: {path}")
    text = path.read_text(encoding="utf-8")
    m = _FRONTMATTER.match(text)
    if not m:
        raise RubricError(f"{path}: missing YAML frontmatter (--- id/version ---)")
    meta = yaml.safe_load(m.group(1)) or {}
    rubric_id = meta.get("rubric_id")
    version = meta.get("rubric_version")
    if not rubric_id or not version:
        raise RubricError(f"{path}: frontmatter needs both rubric_id and rubric_version")
    if not re.fullmatch(r"\d+\.\d+\.\d+", str(version)):
        raise RubricError(f"{path}: rubric_version '{version}' must be semver (x.y.z)")
    return Rubric(rubric_id=str(rubric_id), rubric_version=str(version), body=m.group(2))


@lru_cache(maxsize=None)
def base_rubric() -> Rubric:
    return _parse(_RUBRICS_DIR / "_base.md")


@lru_cache(maxsize=None)
def category_rubric(category: str) -> Rubric:
    if category not in CATEGORIES:
        raise RubricError(f"unknown attack_category '{category}'")
    return _parse(_RUBRICS_DIR / f"{category}.md")


def instructions_for(category: str) -> tuple[str, Rubric]:
    """Return (composed judging instructions, the category Rubric) for a category."""
    rubric = category_rubric(category)
    return rubric.compose(base_rubric()), rubric
