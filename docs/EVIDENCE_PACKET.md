# Evidence Packet — Architecture Defense

**Status:** Skeleton for Phase 0 defense. Sections marked `[TODO: Phase N]` are filled
in as the corresponding implementation phase completes; this packet is updated in
place through the week, not rewritten.

---

## 1. Agent Interaction Diagram

See [ARCHITECTURE.md § System Diagram](../ARCHITECTURE.md#system-diagram) for the
current authoritative diagram (Orchestrator ↔ Red Team ↔ Judge ↔ Documentation ↔
Regression Harness, target, exploit DB, observability layer, human approval gate).

---

## 2. Message Schemas

Authoritative source: [`/contracts`](../contracts/). Summary:

| Message | Producer → Consumer | Schema file | Version |
|---|---|---|---|
| `AttackDirective` | Orchestrator → Red Team | `attack_directive.schema.json` | 1.0.0 |
| `AttackAttempt` | Red Team → Judge | `attack_attempt.schema.json` | 1.0.0 |
| `Verdict` | Judge → Orchestrator, Documentation | `verdict.schema.json` | 1.0.0 |
| `VulnReport` | Documentation → Exploit DB | `vuln_report.schema.json` | 1.0.0 |
| `CampaignResult` | Harness/Judge → Orchestrator | `campaign_result.schema.json` | 1.0.0 |
| Error responses (all agents) | any → Orchestrator | `errors.schema.json` | 1.0.0 |

Contract tests: `[TODO: Phase 6-7]` — `/contracts/tests/` validates producer output
and consumer input against each schema; CI fails on drift without a version bump.

---

## 3. Trust Boundaries

| Boundary | Direction | Control |
|---|---|---|
| Orchestrator → Red Team | Directive issuance | Budget cap enforced in the directive itself |
| Red Team → Target (live Co-Pilot) | Untrusted content → real system | Allow-listed target URL only; no other network egress; sandboxed execution |
| Red Team → Judge | Untrusted attempt → evaluator | Judge treats all Red Team input as untrusted; never executes it, only reads transcript |
| Judge → Documentation | Confirmed verdict only | Documentation only triggered on `result != pass`; cannot fabricate a finding without a Judge verdict |
| Documentation → Exploit DB (publish) | Autonomous write → durable record | **Human approval gate** required before `critical` severity is marked published |
| Any agent → Live remediation | N/A | **No agent has write access to the target's production code/config.** Recommendation only. |
| Orchestrator → Harness | Trigger regression | Read-only on exploit DB except for appending replay results |

Full auth model (which agents hold which credentials) is detailed in the ATO-style
evidence packet: `[TODO: Phase 8]`.

---

## 4. Known Failure Modes

Carried from [ARCHITECTURE.md § Known Failure Modes & Recovery](../ARCHITECTURE.md#known-failure-modes--recovery):
Red Team harmful-content egress, Judge drift/agreement collapse, Orchestrator
no-clear-priority state, agent timeout/crash, cascading failure, cost runaway.
Recovery mechanism documented per failure; detection signal named per failure.

---

## 5. Build-vs-Configure Record

See [BUILD_VS_CONFIGURE.md](./BUILD_VS_CONFIGURE.md) — full evaluation of Garak,
OWASP ZAP, Semgrep, Burp Suite, commercial red-team/reporting platforms, LangGraph,
CrewAI, AutoGen, LangSmith, Langfuse, Braintrust.

---

## 6. Outstanding for Later Phases

- `[TODO: Phase 8]` ATO-style packet: architecture + data-flow diagrams, auth model,
  dependency list w/ versions, self-scan results, eval evidence, sample postmortem.
- `[TODO: Phase 8]` Baseline CPU/memory/latency/throughput profile (100-case run).
- `[TODO: Phase 8]` Load test (100 consecutive attack cases) + bottleneck analysis.
- `[TODO: Phase 6-7]` Contract test results (both producer and consumer sides).
- `[TODO: Phase 6]` Ground-truth ledger for Judge drift detection.
