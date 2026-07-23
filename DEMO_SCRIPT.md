# Demo Script & Storyboard (3–5 min) + Social Post

A shot-by-shot script for the submission video, mapped to the live console panels and
CLIs, plus a social-post draft. Target length **5:00** (a 3:00 cut is marked).

- **Console:** https://agentforge-console.onrender.com — operator token **`forge2026`**
- **Terminal:** repo root, venv active (for the two CLI cutaways)
- **Editor:** `reports/AF-2026-0001.md` open in a tab, ready to show

## Pre-flight (do this 5 min before recording — don't film it)

The live agents take ~10–20 s per attempt, so **pre-warm** so the panels already show
results and you narrate over populated screens instead of spinners:

1. Console → **2 · Regression → Run regression** (populates target version + trend).
2. Console → **4 · Orchestrator → Run autonomous loop** once (so hand-off accordions
   exist to expand on camera).
3. Console → **1 · Eval Suite → Run attack suite** with **use Judge** ticked.
4. Enter the token `forge2026` once so the field is remembered.

> Tip: record the "click Run … " moments fresh for authenticity, but keep a pre-warmed
> tab ready to cut to so you're never watching a 20 s spinner on camera. Or speed the
> wait to 2×.

---

## Beat sheet

### 0:00–0:25 — Hook & framing
**SHOW:** top of the console, the four numbered panels scrolling past.
**SAY:** "This is AgentForge — an autonomous, multi-agent platform that attacks a *live*
clinical AI, confirms real vulnerabilities, and writes the reports. Five agents —
Orchestrator, Red Team, Judge, Documentation, and a Regression harness — coordinating
through versioned contracts. Everything you'll see is running live against a real target
handling patient data."

### 0:25–1:05 — Eval Suite (panel 1)
**SHOW:** Panel 1 → **Run attack suite** with **use Judge** ticked → results-by-category
tiles → **expand a `fail` row**: attack query → target response → **Judge verdict** chip.
**SAY:** "The eval suite runs versioned attack cases across the OWASP-LLM categories.
Deterministic detectors give a fast signal, but an Opus-4.8 **Judge** is the authority —
here it confirms the target leaked PHI. Every result shows the exact attack, the target's
reply, and the Judge's rationale."

### 1:05–1:50 — Red Team (panel 3)
**SHOW:** Panel 3 → **Generate & attack** (data_exfiltration) → the generated attack (note
it says *"the current patient"*, not a name) → target over-discloses the chart → **Judge
verdict: EXPLOIT, critical, escalated**. *(Optional: tick "hostile framing" → show the
OpenRouter fallback banner.)*
**SAY:** "The Red Team generates novel attacks on a cheap open model, and it's
target-aware — it learned this target has no patient lookup, so it attacks *the current
patient* directly. The target dumps the record; the Judge independently confirms a
critical exploit. If the safety-tuned model refuses, it automatically fails over to an
uncensored one."

### 1:50–2:45 — Orchestrator: the autonomous loop (panel 4)
**SHOW:** Panel 4 → **Plan next attack** (category scores with the coverage / high-sev /
regression breakdown) → **Run autonomous loop** → the **collapsed hand-off accordions** →
**expand one**: the `AttackDirective` card + the live Red Team attack + the Judge verdict.
**SAY:** "This is the strategy layer. The Orchestrator reads the state — coverage, open
high-severity findings, regressions — scores the categories, and hands the Red Team a
directive. It runs the loop autonomously, feeding each outcome back so its priorities
shift, all under a spend budget and a kill-switch. Each hand-off shows exactly what the
Red Team did and how the Judge scored it."

### 2:45–3:25 — Regression (panel 2)  *(3-min cut: end here + jump to close)*
**SHOW:** Panel 2 → **Run regression** → summary tiles → the table: **2 still reproduce**,
defenses **stable**, one **alert**.
**SAY:** "Once an exploit is confirmed, it can never silently come back. The Regression
harness replays the exact sequences and asserts the *violated invariant* — not a string —
so a reworded leak still fails. It's fully deterministic: no model, no cost, runs in CI on
every deploy."

### 3:25–4:05 — Reports & the human gate
**SHOW:** cut to the editor → `reports/AF-2026-0001.md` (scroll: severity, minimal attack
sequence, reproduction steps, remediation) → then `reports/README.md` listing all four.
**SAY:** "Confirmed exploits become professional vulnerability reports a senior engineer
could fix from text alone. And there are guardrails: a *critical* report is invalid until
a human approves it, and the platform never remediates the target on its own — it
documents; humans decide."

### 4:05–4:40 — Observability & cost (terminal cutaway)
**SHOW:** terminal → `python -m agentforge.observability` → the dashboard (cases/category,
resilience by version, vuln status, run cost, **per-agent timeline**).
**SAY:** "Everything's observable from the state the agents already write — resilience over
target versions, open findings, cost, and a per-agent action timeline that makes every
autonomous step auditable. We profiled it too: the bottleneck is external API latency, not
our code, and the Opus Judge is 95% of the cost — both with a clear scaling path."

### 4:40–5:00 — Close
**SHOW:** back to the console, all four panels.
**SAY:** "AgentForge — a full adversarial-evaluation loop running live against a real
clinical AI. Four confirmed vulnerabilities, every one reproducible. Built for
@GauntletAI."
**SHOW (end card):** repo URL + live console URL.

---

## Recording tips
- 1080p, capture the browser at ~90% zoom so a whole panel fits; bump console font if needed.
- Pre-warm (above) so no shot waits on a spinner; speed any unavoidable wait to 2×.
- Keep the token field filled; don't show the raw token on screen longer than a blink.
- The synthetic patient (Phil Belford) is test data — fine to show; say "synthetic" once.
- Have `AI_COST_ANALYSIS.md` / `PERF_PROFILE.md` open in tabs for optional B-roll.

---

## Social post — draft (tag @GauntletAI)

**X / short:**
> Built AgentForge for @GauntletAI: an autonomous multi-agent platform that attacks a live
> clinical AI, confirms real exploits with an Opus-4.8 Judge, and writes the vuln reports —
> itself. 5 agents, versioned contracts, human gates on anything critical.
>
> It found 4 confirmed PHI-disclosure vulns. Every one reproducible. Live demo 👇
> [console URL] · code: [repo URL]

**LinkedIn / long:**
> **AgentForge — autonomous adversarial evaluation for clinical AI** (built for
> @GauntletAI).
>
> I built a platform that red-teams a live clinical co-pilot end-to-end: an **Orchestrator**
> scores where to attack, a target-aware **Red Team** (open model, auto-failover) generates
> the attacks, an **Opus-4.8 Judge** independently confirms whether the target actually
> failed, a **Documentation agent** writes the vulnerability report, and a deterministic
> **Regression harness** guarantees a fixed exploit can never silently return.
>
> The agents coordinate only through **versioned JSON-Schema contracts** (both sides
> tested), and humans stay in the loop where it matters — a critical report is invalid
> until approved, and the platform never remediates on its own.
>
> Result: **4 confirmed, reproducible PHI-disclosure vulnerabilities**, plus a full cost
> analysis (the frontier Judge is ~95% of spend, with a clear path to 16× cheaper at scale)
> and a perf profile (bottleneck = external API latency, not the framework).
>
> Live console + code in the comments. #AIsecurity #LLMsecurity #redteam
