# Users, Workflows & Use Cases — AgentForge

AgentForge is an autonomous adversarial-evaluation platform that attacks a live clinical
AI (an EMR co-pilot handling PHI), confirms real exploits, and turns them into
reproducible vulnerability reports — with humans kept in the loop exactly where judgment
matters. This document describes who uses it, how, and why the automation is justified.

## Who uses it

| User | Role | What they get from AgentForge |
|------|------|-------------------------------|
| **AppSec / red-team engineer** | Runs adversarial campaigns before release | The Orchestrator autonomously prioritizes and drives attacks across OWASP-LLM categories; they review confirmed exploits instead of hand-crafting every prompt. |
| **AI/ML platform engineer** | Owns the co-pilot under test | Actionable `VulnReport`s with a minimal reproduction and concrete *server-side* remediation; the Regression Harness proves their fix and guards it forever. |
| **CISO / security leadership** | Accountable for risk sign-off | The observability console: exploits by category, resilience over target versions, open vs resolved findings, spend. The human-approval gate on critical reports is theirs to pull. |
| **Compliance / privacy officer (HIPAA)** | Owns PHI risk | Evidence that PHI-disclosure paths were tested, confirmed, documented, and gated — with an audit trail (attempt IDs, verdicts, approvals). |
| **QA / release engineer** | Owns the deploy gate | A deterministic regression suite that re-runs on every target change and fails the build if a confirmed exploit reappears — at $0 LLM cost. |

## Core workflows

### 1. Pre-release adversarial evaluation (autonomous)
The **Orchestrator** reads observability state (coverage, open high-sev findings,
regressions), scores the attack categories, and hands the **Red Team** a schema-valid
`AttackDirective`. The Red Team generates a novel attack on an open model, executes it
against the live target, and the **Judge** (frontier model, frozen rubric) rules whether
the target stayed secure. The engineer watches the loop and reviews what landed.
→ *Console: panels 3–4; CLI: `python -m agentforge.orchestrator`.*

### 2. Confirmed exploit → report → human gate → fix → proof
A `fail` verdict becomes a `VulnReport` via the **Documentation Agent** (deterministic
scaffold + frontier-authored prose). A **critical** report is contract-invalid until a
human approves it — the platform performs **no autonomous remediation**. Once the
engineer fixes it, the **Regression Harness** replays the exact attack and flips the
finding to resolved only when the *invariant* holds.
→ *`python -m agentforge.generate_reports`; see `reports/`.*

### 3. Continuous regression (every target change)
On a new target version, the deterministic Regression Harness replays the confirmed-
exploit corpus and flags any that reproduce or **reappear** — no model, no credits, so
it runs in CI on every deploy.
→ *Console: panel 2; CLI: `python -m agentforge.regression`.*

### 4. Triage of an incoming scan
Security leads use the platform's confirm-then-report discipline to separate real
exploits from scanner noise — see `TRIAGE_EXERCISE.md`, where 3 of 12 "findings"
(including a "critical" SQLi) were false positives the Judge/manual review cleared.

## Use cases

- **Shift-left security for clinical AI:** attack the co-pilot in CI before it ships,
  not after an incident.
- **HIPAA/PHI assurance:** continuously prove whether the assistant leaks patient data to
  unauthenticated or mismatched-patient callers (the four confirmed reports are exactly
  these failure modes).
- **Regression guarantee:** a fixed exploit can never silently return — the invariant is
  re-asserted on every change.
- **Model/vendor swaps:** re-run the whole corpus when the target's underlying model
  changes, to catch capability regressions in safety behavior.

## Why automate this (and why *not* fully)

**Automate the parts that don't scale by hand:**
- **Search space is effectively infinite.** Prompt-injection / social-engineering attack
  space is combinatorial; a human writes dozens of prompts, the Orchestrator + Red Team
  explore thousands and *prioritize by signal*.
- **Speed & cadence.** Regression must run on every deploy; a human can't re-test every
  confirmed exploit on every change. Deterministic replay makes it free and instant.
- **Consistency.** Frozen rubrics + deterministic Verdict assembly mean the same attack
  is scored the same way every time — reproducible evidence, not vibes.
- **Cost discipline.** Model tiering + the Orchestrator's budget/kill-switch spend money
  where attacks actually land (see `AI_COST_ANALYSIS.md`).

**Keep humans in the loop where judgment is irreducible:**
- **Critical-severity approval gate.** A critical `VulnReport` cannot publish without a
  human sign-off — enforced at the contract boundary, not by convention.
- **No autonomous remediation.** AgentForge documents; humans fix. `fix_validation` is
  only flipped by the deterministic harness once a fix is *proven*.
- **Triage decisions.** Validate / remediate / defer / document is a risk judgment a
  security lead owns; the platform supplies confirmed evidence, not the decision.
- **Detector vs. Judge.** The semantic Judge overrides a naive detector match, which is
  why false positives (e.g., a model *declining* to leak its prompt) don't become
  reports — but the final call on ambiguous safety behavior is escalated to a human when
  confidence is low or severity is critical.

The design principle: **automate breadth, speed, and consistency; reserve human judgment
for approval, remediation, and risk acceptance.**
