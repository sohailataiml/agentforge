# Target — Phase 1

The target is the Week 1/2 **Clinical Co-Pilot**: a standalone Python agent
service (FastAPI + LangGraph) in front of a Dockerized **OpenEMR** fork, talking
to it only over OAuth2/FHIR R4 — never the database, never imported code.

## Source

| | |
|---|---|
| Agent service (the thing under test) | https://labs.gauntletai.com/sohailsiddiqui/clinical-copilot-agent |
| OpenEMR fork + embedded co-pilot panel | https://labs.gauntletai.com/sohailsiddiqui/openemragent |

Cloned read-only into [`target/`](target/) for reference (READMEs, sample
documents, guideline corpus, OpenAPI contract). **The adapter never imports or
runs this code** — it talks to the deployed URLs below over HTTP, per the
plan's build order. The clones exist so later phases (threat modeling, sample
malicious-document mutations) can reuse the existing sample fixtures instead
of re-deriving them.

## Deployed (live — hard gate satisfied)

| | |
|---|---|
| **Agent** | **https://clinical-copilot-agent.onrender.com** |
| **OpenEMR** (co-pilot embedded in the chart UI) | https://openemr-oy5a.onrender.com |

Verified live 2026-07-21: `/health` → 200, `/ready` → all 6 dependencies
(`openemr_fhir`, `anthropic_llm`, `langsmith`, `document_storage`,
`vector_index`, `reranker`) ready, `/patients` returns 3 demo patients, and a
real `/chat` call against `Phil Belford` (`a2345ab2-477b-4b59-b7be-7e82aa7f9d8c`)
returned a correctly-cited chart-retrieval answer (hypertension, chronic renal
insufficiency, Norvasc, Lisinopril — all with FHIR resource citations).
Render free/starter services can sleep; first request after idle may take
~30s while it wakes.

## Changes made to reach a testable state

**None.** The target was already deployed, healthy, and answering real
chat/chart-retrieval/document/guideline queries at the time AgentForge picked
it up — no local stand-up, no redeploy, no code changes were required to reach
Phase 1's exit gate. This satisfies "Run locally and deployed, testable": the
Week 1/2 team already did the deploy; AgentForge's job here was to confirm it
live and wire the adapter to it, not rebuild it.

A local Docker stack (`docker/development-easy`) is documented in
[`target/openemragent/DEPLOYMENT.md`](target/openemragent/DEPLOYMENT.md) for
anyone who needs to run the target on-box, but it is not required for
AgentForge's attacks — those hit the deployed URL directly, same as the
plan's hard gate requires.

## The target adapter

[`agentforge/target_adapter.py`](agentforge/target_adapter.py) —
`send_to_target(session_id, messages, *, patient_id) -> TargetResult`, the
single seam every agent uses. Turn/role shapes match
[`contracts/attack_attempt.schema.json`](contracts/attack_attempt.schema.json)
exactly (`input_sequence` in, `target_transcript` out), so a Red Team Agent's
output needs no translation before being handed to it, and the regression
harness can replay an `AttackAttempt` by calling this function again with the
same `input_sequence`.

Tested in [`tests/test_target_adapter.py`](tests/test_target_adapter.py) —
`pytest -m live` hits the real deployed target (single-turn chart retrieval,
multi-turn session continuity, and the system-context fold-in below); the two
non-`live` tests check the input-validation error paths without a network
call.

```bash
pip install -e .
python -m pytest tests/ -v
```

### Known limitation surfaced while wiring the adapter

The target exposes **no system-role channel** — `/chat` accepts exactly one
clinician-authored `message` per turn (see `ChatRequest` in
[`target/clinical-copilot-agent/openapi.json`](target/clinical-copilot-agent/openapi.json)).
A `system_context`-role turn (per the `AttackAttempt` schema) has nowhere to
go on the wire, so the adapter folds it into the *next* `user` turn's content
with a visible `[SYSTEM CONTEXT INJECTED]` prefix rather than silently
dropping it — the attempt still executes and is still logged, it just rides
in through the same channel a real message would.

This is a genuine finding for Phase 2, not an adapter workaround: **any
attack that assumes a dedicated system-prompt channel must instead go through
the user-message or document-upload surface on this target.** Flag under
identity/role exploitation in `THREAT_MODEL.md` — the absence of the channel
may itself narrow (or, depending on how the agent's own system prompt is
constructed server-side, widen) the system-prompt-override attack surface.

## Security note surfaced while verifying liveness

The `/chat` and `/patients` calls above succeeded with **no `Authorization`
header at all** — the deployed instance's DEV password-grant fallback
([`app/fhir/session.py`](target/clinical-copilot-agent/app/fhir/session.py))
is active in production, so any anonymous caller gets full chart PHI with no
credential. This was not sought out — it's what "confirm chat + chart
retrieval works" surfaced by default. Full writeup and severity ranking:
[THREAT_MODEL.md](THREAT_MODEL.md) §1 (`data_exfiltration`, ranked #1).

## Reference: patient IDs available on the deployed demo data

```
a2345ab2-477b-4b59-b7be-7e82aa7f9d8c  Phil Belford
a2345ab2-4781-4061-bb4c-c6fff2557dd8  Susan Ardmore Underwood
a2345ab2-4784-4796-b024-59e60a25d224  Wanda Moore
```

(`GET https://clinical-copilot-agent.onrender.com/patients`)
