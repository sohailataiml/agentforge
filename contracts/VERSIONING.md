# Contract Versioning & Migration

The seven inter-agent messages in this directory are the *only* coupling between
agents — they talk through versioned JSON Schemas, never through shared code. This
note is the policy for evolving them without breaking a running loop.

## Boundaries

| Contract | Producer | Consumer(s) |
|----------|----------|-------------|
| `eval_case` | case authoring (YAML) | Eval Runner |
| `eval_result` | Eval Runner | Dashboard / observability |
| `attack_attempt` | Red Team | Judge, Regression |
| `attack_directive` | Orchestrator | Red Team |
| `verdict` | Judge | Documentation, Regression, Orchestrator |
| `vuln_report` | Documentation Agent | report reader / Exploit DB |
| `campaign_result` | Regression Harness | Orchestrator |
| `errors` | any agent | any agent |

Both sides are tested together in `tests/test_contracts.py`: the real producer emits
a message, it is validated against the schema, and the real consumer parses it.

## Versioning rules (SemVer on `schema_version`)

Every message carries `schema_version`, declared in each schema as a **`const`**. The
`const` is deliberate: a producer cannot silently emit a new shape — the version is
part of the payload, and changing behavior *requires* changing the const, which trips
the contract tests until both sides are updated.

- **PATCH / MINOR — additive, backward-compatible.** Adding an **optional** field, or
  widening an `enum`, is compatible. Bump the minor (`1.0.0 → 1.1.0`). Old consumers
  ignore fields they… — **caveat:** every schema sets `additionalProperties: false`
  (fail-closed), so even an additive field is only accepted once the consumer's schema
  copy is updated. Roll the schema to consumers first, producers second.
- **MAJOR — breaking.** Adding/removing a **required** field, renaming, changing a type,
  or narrowing an `enum` is breaking. Bump the major (`1.0.0 → 2.0.0`) and follow the
  migration procedure.

## Migration procedure (major bump)

1. **Write the new schema** as `contracts/<name>.schema.json` with the new
   `schema_version` const, and record the change in the log below.
2. **Update the consumer first** to accept both versions during the transition
   (dispatch on `schema_version`), so in-flight/older messages still parse.
3. **Update the producer** to emit the new version.
4. **Update `tests/test_contracts.py`** — the both-sides test is the gate; it must pass
   for the new version before either side ships.
5. **Regression corpus:** stored exploits embed a frozen `case_json` at their authored
   version. A reader must migrate on load, not assume the current version — the
   Regression Harness's stored `case_json` is intentionally self-contained so an old
   corpus stays replayable.
6. Once no producer emits the old version and no stored data references it, drop the
   dual-read path.

## Compatibility guarantees

- `additionalProperties: false` everywhere → **unknown fields are rejected**, not
  ignored. This is fail-closed on purpose: a field a consumer doesn't understand is a
  version mismatch, not something to skip silently.
- Conditional invariants live in the schema where possible (e.g. `vuln_report` requires
  `human_approved: true` when `severity == "critical"`; `verdict` escalation), so the
  gate can't be bypassed by an out-of-band producer.
- Numeric/logical invariants that JSON Schema can't express (confidence clamping,
  escalation rules) are enforced in the producer's assembly code and re-checked against
  the schema before the message leaves.

## Migration log

| Date | Contract | From → To | Change |
|------|----------|-----------|--------|
| 2026-07 | *(all)* | — → 1.0.0 | Initial versioned contracts. |

_No breaking migrations yet — all contracts are at 1.0.0._
