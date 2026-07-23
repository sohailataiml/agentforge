# ATO-Style Evidence Packet — AgentForge

An Authority-to-Operate–style assurance package: the evidence an authorizing official
would review before allowing AgentForge to run against a system. It assembles the
architecture, authorization boundary, access-control model, supply chain, self-scan
results, evaluation evidence, and a sample incident postmortem into one place.

> **Categorization.** AgentForge is an internal **security-testing tool** that attacks a
> Clinical Co-Pilot. It handles **synthetic** patient records (test data, no real PHI),
> which is why it is safe to deploy on a public host. If ever pointed at a system holding
> real PHI, it would inherit that system's data categorization (HIGH confidentiality) and
> the controls in §4 become mandatory, not advisory.

## 1. System identification

| Field | Value |
|-------|-------|
| System name | AgentForge — Multi-Agent Adversarial Evaluation Platform |
| Purpose | Autonomously attack, confirm, and document vulnerabilities in a clinical AI |
| Data types | Synthetic patient records (test PHI); no production data |
| Deployment | FastAPI console on Render; CLI agents run locally/CI |
| Source of record | GitHub + GitLab (public); contracts in `contracts/`, versioned |
| Authorizing artifacts | This packet + `ARCHITECTURE.md`, `THREAT_MODEL.md`, `reports/`, `AI_COST_ANALYSIS.md`, `OBSERVABILITY.md`, `PERF_PROFILE.md`, `TRIAGE_EXERCISE.md` |

## 2. Authorization boundary & architecture

```mermaid
flowchart TB
  U[Operator] -->|CONSOLE_TOKEN| C[Console FastAPI]
  C --> O[Orchestrator - deterministic]
  O -->|AttackDirective| RT[Red Team Agent]
  RT --> G[Groq open model]
  RT -. refusal .-> OR[OpenRouter fallback]
  RT -->|attack| T[Target Clinical Co-Pilot - synthetic PHI]
  T -->|transcript| J[Judge - Anthropic Opus]
  J -->|Verdict| DOC[Documentation Agent]
  DOC -->|VulnReport| R[(reports)]
  O --> RH[Regression Harness - deterministic]
  RH -->|replay| T
  R -->|open findings| O
```

Everything crosses an agent boundary only through a **versioned JSON-Schema contract**
(`contracts/`, both-sides tested). The deterministic control plane (Orchestrator,
Regression, detectors) makes no external LLM calls.

## 3. Data-flow diagram

```mermaid
flowchart LR
  ENV[env vars - GROQ OPENROUTER JUDGE CONSOLE_TOKEN] -. secrets .-> AF[AgentForge]
  AF -->|attack prompt| T[Target chat - synthetic PHI]
  T -->|transcript plus PHI| AF
  AF -->|attack plus transcript, no secrets| J[Judge Opus]
  AF -->|confirmed exploit plus evidence| DOC[Documentation]
  DOC -->|VulnReport JSON and MD| FS[(reports - synthetic)]
  AF -->|eval_result run logs| L[(evals results - synthetic)]
```

**PHI in transit/at rest is synthetic.** The only real secrets are provider API keys and
the console token, which live **only** in environment variables (§4) and never enter a
prompt, a log, a report, or the repo. An **egress screen** (`red_team.egress_ok`) blocks
any attack payload that would exfiltrate a secret-shaped string — tested in
`tests/test_red_team.py`.

## 4. Authentication & access-control model

| Control | Mechanism | Evidence |
|---------|-----------|----------|
| Operator auth to the console's paid actions | `CONSOLE_TOKEN` header gate; unset only for local dev | `webapp._require_token`; `tests/test_webapp.py::test_actions_require_token_when_set` |
| Read-only endpoints | Open (no cost, no state change) | `/api/config`, `/api/orchestrator/plan` |
| Secret management | Provider keys + token via **env vars only**; never committed | Secret scan §6; `AI_COST_ANALYSIS`/README posture |
| Secret egress prevention | Egress screen strips/blocks secret-shaped attack payloads | `tests/test_red_team.py::test_egress_blocks_real_secret_and_allows_normal` |
| Human-in-the-loop gate | A **critical** `VulnReport` is contract-invalid unless `human_approved` | `contracts/vuln_report.schema.json` conditional; `tests/test_documentation.py` |
| No autonomous remediation | Platform documents only; `fix_validation.validated` flipped solely by the Regression Harness | `documentation.py`; `ARCHITECTURE.md` |
| Target-side scoping (defense in depth) | Target's tools are server-side bound to one open patient | Threat model; `red_team._roster_context` |

**Note on the target's own auth:** the platform's core finding is that the *target* has
**no** authentication on PHI disclosure (see `reports/AF-2026-0001`). That is the system
under test's gap, documented — not AgentForge's.

## 5. Dependency inventory & supply chain

Runtime surface is deliberately small — **four** direct runtime dependencies, all pinned
with upper bounds; Python `>=3.12,<3.15`.

| Package | Version | Role |
|---------|---------|------|
| `httpx` | 0.27.2 | HTTP to target + OpenAI-compatible providers |
| `jsonschema` | 4.26.0 | Contract validation (both sides) |
| `pyyaml` | 6.0.3 | Eval-case authoring |
| `anthropic` | 0.109.2 | Judge / Documentation (Opus) |
| `fastapi` / `starlette` | 0.115.14 / 0.46.2 | Console (web extra) |
| `uvicorn` | 0.32.1 | Console server (web extra) |
| `pytest` / `ruff` | 8.4.2 / 0.7.4 | Dev/test/lint (not shipped) |

Provider access is behind a single **OpenAI-compatible seam**, so a compromised or
deprecated provider can be swapped without touching agent logic.

## 6. Self-scan / vulnerability assessment

Run against AgentForge's **own** code and supply chain (dogfooding the security posture):

| Scan | Tool | Result |
|------|------|--------|
| Static analysis | `bandit -r agentforge` | **0 High, 1 Medium, 3 Low — all false positives** (see below), 3,577 LOC |
| Secret scan | `git grep` for `gsk_/sk-ant-/sk-or-/rnd_` in tracked non-doc files | **Clean** — the only hit is a *deliberate fake* key in `test_red_team.py` that verifies the egress screen |
| Lint | `ruff check` | Clean |
| Test suite | `pytest -m "not live"` | **126 passing**; 9 live-marked |
| Judge accuracy | `agentforge.judge_eval` vs 12-entry ground truth | ≥90% target (frozen rubrics) |

**Triage of the bandit findings (all false positives — same discipline as
`TRIAGE_EXERCISE.md`):**
- `B105` ×3 "hardcoded password" — the literals `1`, `0`, `512` are a step-precedence
  map, a detector rank map, and a token-budget default; none are credentials.
- `B608` "SQL injection" — the only string concatenation is a **constant** `WHERE
  category = ?` clause whose value is a **bound parameter**; no user data enters the SQL.

An earlier real incident (a key captured into a settings file during development) was
detected, the lines removed, and the key flagged for rotation — see §8.

## 7. Evaluation evidence (the platform works)

- **4 confirmed vulnerability reports** across 3 categories, each reproducible from text
  alone (`reports/AF-2026-0001..0004`), produced from confirmed Judge verdicts.
- **Regression corpus** replays deterministically; live runs show 2 confirmed exploits
  reproducing and defended boundaries holding (`OBSERVABILITY.md`).
- **Both-sides contract tests** for all 7 inter-agent boundaries (`tests/test_contracts.py`).
- **Detector-vs-Judge discipline:** false-positive detector hits (e.g. a model *declining*
  to leak its prompt) are cleared by the Judge and never reported.

## 8. Sample postmortem — AF-2026-0001 (Unauthenticated PHI disclosure)

**Summary.** The Clinical Co-Pilot returned a named patient's PHI (problems, medications)
over `/chat` to a caller with **no credential**. Confirmed by the Judge (severity
critical), documented as `AF-2026-0001`, human-approved, and added to the regression
corpus.

**Timeline (UTC).**
| When | Event |
|------|-------|
| T0 | Orchestrator scored `data_exfiltration` highest (open coverage + high-sev); issued an `AttackDirective`. |
| T0+~12s | Red Team (open model) generated a direct unauthenticated retrieval; target executed it and returned the chart. |
| T0+~20s | Judge ruled `fail` / critical; escalated to human. |
| T0+minutes | Documentation Agent authored `AF-2026-0001`; operator approved (critical gate). |
| Ongoing | Regression Harness replays the exact sequence on every target change. |

**Root cause.** Authorization is not enforced at the tool-call boundary; the model is
trusted to self-police disclosure, and it doesn't. In-message role/identity claims carry
no verified authorization (cf. `AF-2026-0004`).

**Impact.** Any anonymous caller can harvest identifiable patient records — a HIPAA
breach class. (Synthetic data here; real-world impact would be severe.)

**Remediation (recommended, not auto-applied).** Enforce an authenticated, patient-scoped
session at the tool gateway before any chart read; treat in-message role claims as
untrusted. **Validation:** the fix is proven only when the regression case flips
`fail → pass` and stays there — the harness, not a human assertion, closes the finding.

**Prevention / lessons.** (1) Deterministic authz belongs *below* the model, not in it.
(2) The confirm-then-document discipline (Judge over detector) kept the report set free of
false positives. (3) The human-approval gate ensured a critical finding wasn't published
or acted on autonomously.

## 9. Continuous monitoring & POA&M

- **Monitoring:** the observability queries (`OBSERVABILITY.md`) track resilience by
  target version, open/resolved vulns, and a per-agent action timeline (audit trail).
- **Regression gate:** deterministic replay on every target change; CI-fail on
  reappearance (`agentforge.regression` non-zero exit on alert).
- **POA&M (open items):** the four confirmed findings remain `open` pending the target
  team's fixes; the platform's own bandit/secret posture is clean. Rotate any development
  keys before production use.
