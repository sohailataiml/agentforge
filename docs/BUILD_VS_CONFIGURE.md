# Build-vs-Configure Decision Record

**Phase:** 0 — Architecture Defense
**Question:** For each required capability, should AgentForge configure an existing
tool or build a custom agent? This record is evaluated before any agent role is
implemented, per the required Architecture Defense deliverable.

---

## Method

For each capability we list: existing tools evaluated, what they cover, where they
fall short for a **multi-turn, stateful, LLM-mediated clinical chatbot**, and the
resulting decision. Default posture: **configure first, build only where the tool's
model doesn't fit.**

---

## 1. Attack generation / fuzzing

**Tools evaluated:** Garak (LLM vulnerability scanner), OWASP ZAP, custom fuzzers.

| Tool | Covers | Falls short here |
|------|--------|-------------------|
| **Garak** | Large library of static/templated LLM probes (prompt injection, jailbreak, data leakage patterns); good single-turn coverage; pluggable "generators" | No native multi-turn conversation state; probes are largely static/templated, not adaptively mutated based on a partial success signal against *this* target's specific refusal patterns; no healthcare/PHI-specific probe set out of the box; not designed to consume a Judge's verdict and re-attack |
| **OWASP ZAP** | Excellent for classic web vuln scanning (the OWASP Web Top 10 slice: SSRF, injection, auth) | No concept of an LLM conversation, tool-call semantics, or prompt-level adversarial mutation at all — it's HTTP/web-layer, not conversation-layer |
| Custom fuzzer (raw) | Full control | Reinvents payload libraries Garak already has |

**Decision:** **Hybrid.** Configure Garak as a **seed-probe source** feeding the
initial attack suite (Phase 3) and as a baseline single-turn regression check. **Build**
a custom Red Team Agent for what Garak cannot do: multi-turn sequencing, variant
mutation driven by the Judge's partial-success signal, and target-specific adaptation
against the Co-Pilot's actual tool-calling surface. Garak's probes become
`seed_cases` referenced in `AttackDirective`, not a replacement for the agent.

---

## 2. Attack evaluation ("did this succeed?")

**Tools evaluated:** Regex/keyword matchers, Semgrep (code-pattern matching),
commercial LLM-eval platforms (e.g. hosted judge-as-a-service).

| Tool | Covers | Falls short here |
|------|--------|-------------------|
| **Semgrep** | Excellent for static code pattern matching (e.g. scanning the Co-Pilot's own source for injection-prone code, unsafe tool definitions) | Not applicable to *runtime conversational output* — it has no way to judge whether a free-text chatbot response leaked PHI or violated a clinical safety boundary |
| Regex/keyword matcher | Deterministic, fast, cheap | Cannot judge semantic success (e.g. "did the assistant impersonate a clinician" or "did it leak PHI phrased differently than the keyword list") — brittle against paraphrase |
| Commercial hosted judge APIs | Convenient | Opaque rubric, cannot be frozen/versioned to our specification, adds a third-party trust dependency for a healthcare-adjacent verdict of record |

**Decision:** **Build** the Judge Agent — semantic judgment against a frozen,
versioned, healthcare-specific rubric is the core differentiator this assignment
asks for, and no off-the-shelf tool exposes a rubric we can freeze/version/ground-
truth-test ourselves. **Configure** Semgrep separately (not as the Judge) to scan
the Co-Pilot's own source and tool definitions for classic insecure-output-handling
patterns — this feeds the threat model, not the runtime Judge.

---

## 3. Deterministic replay / regression

**Tools evaluated:** Standard test frameworks (pytest), Burp Suite (Repeater/Intruder
for HTTP replay), custom harness.

| Tool | Covers | Falls short here |
|------|--------|-------------------|
| **Burp Suite** | Mature HTTP request replay, Intruder for parameterized re-sends | Built for HTTP request/response, not multi-turn conversational state with session/context carry-over; no native concept of an "invariant" (e.g. "no cross-patient PHI") to assert on free-text output; commercial license friction for CI automation |
| **pytest** (+ custom assertions) | Full control, free, CI-native, easy to version | Nothing out of the box for LLM-specific invariant checking — must be built regardless |

**Decision:** **Build** the Regression Harness on pytest as the runner, with custom
invariant-assertion functions (PHI-pattern checks, cross-patient-leak checks,
tool-call boundary checks) — because the reproducibility requirement ("did the
invariant actually hold, not did the string match") is bespoke to this domain and no
tool ships it. Burp is not used; its request/response model doesn't fit a stateful
chat session well enough to justify the license/integration cost.

---

## 4. Orchestration / coordination framework

**Tools evaluated:** LangGraph, CrewAI, AutoGen, fully custom state machine.

| Tool | Covers | Falls short here |
|------|--------|-------------------|
| **CrewAI** | Fast to prototype role-based crews | Coordination is implicit/role-prompt-driven rather than an explicit typed graph; weaker durable-checkpoint story for resuming a failed overnight run |
| **AutoGen** | Strong multi-agent conversation patterns | Optimized for agents *talking to each other in natural language*, not for a typed, schema-validated message contract between agents with different trust levels — would require bolting on the contract layer anyway |
| **LangGraph** | Explicit graph of nodes/edges with typed state, durable checkpoints, per-node retry/resume | Steeper setup than CrewAI for the simplest case |
| Fully custom | Full control | Reinvents checkpointing/retry semantics for no benefit |

**Decision:** **Configure LangGraph.** The explicit typed-state graph is the closest
existing fit to "agents hand off validated JSON messages, not shared mutable
context," and its checkpointing directly answers the "what happens when one agent
fails mid-pipeline" requirement without custom infrastructure.

---

## 5. Observability / tracing

**Tools evaluated:** LangSmith, Langfuse, Braintrust, fully custom logging.

| Tool | Covers | Falls short here |
|------|--------|-------------------|
| **LangSmith** | Deep LangGraph integration, good tracing | Vendor-tied to LangChain ecosystem billing; less natural fit for a security-findings data model (severity, coverage, regression) |
| **Braintrust** | Strong eval-centric UI | Eval-experiment-centric, less natural for long-lived security run history / coverage trend queries |
| **Langfuse** | Open-source, self-hostable, agent/session tracing, cost tracking per call | Doesn't natively model "coverage by attack category" or "vuln status" — needs a custom metrics layer on top regardless |

**Decision:** **Configure Langfuse** for raw inter-agent trace + cost capture
(self-hostable, keeps healthcare-adjacent data on infrastructure we control) **+
build** a thin custom metrics layer (SQL queries over the exploit DB) for the
security-specific questions (coverage, resilience trend, open/resolved vulns) that
no generic LLM-observability tool answers out of the box.

---

## 6. Vulnerability documentation / report generation

**Tools evaluated:** Commercial red-team reporting platforms (e.g. PlexTrac-style),
manual templates.

| Tool | Covers | Falls short here |
|------|--------|-------------------|
| Commercial reporting platforms | Polished report templates, workflow | Built for human pentesters filing reports, not for an autonomous agent producing schema-validated, data-quality-checked reports from a `Verdict` object; licensing overhead disproportionate to project scope |
| Manual template | Simple | Not automatable, defeats the "without requiring a human to write them" requirement |

**Decision:** **Build** the Documentation Agent — the requirement is explicitly that
report generation is autonomous and schema-validated against our own exploit-DB
data model; no COTS tool takes a `Verdict` object as input.

---

## Summary table

| Capability | Decision | Primary tool(s) |
|---|---|---|
| Attack generation | Hybrid — configure + build | Garak (seeds) + custom Red Team Agent |
| Attack evaluation | Build | Custom Judge Agent |
| Source-level scanning | Configure | Semgrep (feeds threat model, not runtime Judge) |
| Web-layer scanning | Configure (supplemental) | OWASP ZAP (classic web surface only) |
| Deterministic replay | Build | pytest + custom invariant assertions |
| Orchestration framework | Configure | LangGraph |
| Observability | Configure + build (metrics layer) | Langfuse + custom SQL views |
| Documentation | Build | Custom Documentation Agent |

**Guiding principle applied throughout:** configure a tool wherever its existing
model already fits the capability; build only where the capability requires
domain-specific state (multi-turn conversation, healthcare invariants, versioned
rubrics) that no evaluated tool represents natively.
