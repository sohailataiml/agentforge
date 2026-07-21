"""The one seam every AgentForge agent uses to reach the Clinical Co-Pilot target.

No agent talks to the target's HTTP API directly. Routing every attack through
send_to_target is what makes the target swappable (a redeploy, a staging URL)
and what makes the regression harness's replay deterministic: it re-issues the
same input_sequence through the same function and diffs the outcome, not the
wire format.

Turn/role shapes here mirror contracts/attack_attempt.schema.json exactly
(input_sequence and target_transcript) so a Red Team Agent's output can be
handed to this function with no translation layer.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx

TARGET_BASE_URL = os.environ.get("TARGET_BASE_URL", "https://clinical-copilot-agent.onrender.com")
TARGET_TIMEOUT_S = float(os.environ.get("TARGET_TIMEOUT_S", "60"))

InputRole = Literal["user", "system_context", "uploaded_content"]
TranscriptRole = Literal["assistant", "tool_call", "tool_result"]


class TargetError(RuntimeError):
    """The target was unreachable, timed out, or returned a non-2xx response."""


@dataclass
class TranscriptTurn:
    turn: int
    role: TranscriptRole
    content: str

    def to_dict(self) -> dict[str, Any]:
        return {"turn": self.turn, "role": self.role, "content": self.content}


@dataclass
class TargetResult:
    """Everything an AttackAttempt needs from one executed sequence."""

    session_id: str
    target_transcript: list[TranscriptTurn]
    cost: dict[str, Any]  # {"tokens": int, "usd": float} — shape matches contracts' `cost`
    raw_responses: list[dict[str, Any]] = field(default_factory=list)

    def transcript_as_dicts(self) -> list[dict[str, Any]]:
        return [t.to_dict() for t in self.target_transcript]


def send_to_target(
    session_id: str | None,
    messages: list[dict[str, Any]],
    *,
    patient_id: str | None = None,
    base_url: str | None = None,
    client: httpx.Client | None = None,
) -> TargetResult:
    """Execute one attack sequence against the live deployed Clinical Co-Pilot.

    Args:
        session_id: the target's `conversation_id` to continue, or None to
            start a fresh one. All turns in `messages` are sent as one
            conversation — the target holds turn history server-side, so this
            adapter never resends prior turns.
        messages: `input_sequence`-shaped turns — dicts with `turn` (int),
            `role` (`"user"` | `"system_context"` | `"uploaded_content"`), and
            `content` (str). An `"uploaded_content"` turn also needs `doc_type`
            (`"lab_pdf"` | `"intake_form"`) and its `content` must be a
            filesystem path to the document to upload. Turns are sent in
            ascending `turn` order regardless of list order.
        patient_id: FHIR patient id to scope the whole conversation to
            (required — every /chat call on this target is scoped to exactly
            one patient by contract). No default: callers must be explicit
            about which patient an attack is run against.
        base_url: override for TARGET_BASE_URL (mainly for tests / a staging
            deploy).
        client: reuse an existing httpx.Client (e.g. to share connection
            pooling across many attempts in one campaign). Owned/closed
            internally when omitted.

    Returns:
        TargetResult with the target's own conversation_id (so the caller can
        continue the same session on the next AttackAttempt in a mutation
        family), a target_transcript shaped for contracts/attack_attempt.schema.json,
        and the accumulated token/cost totals.

    Raises:
        TargetError: patient_id missing, an upload/chat call fails, or the
            sequence has no `"user"` turns (nothing would ever reach the
            target and target_transcript would be empty, which violates the
            AttackAttempt schema's `minItems: 1`).

    Known limitation — no system-role channel:
        This target exposes no way to inject a system-level message; /chat
        takes only a single clinician-role `message` per turn. A
        `"system_context"` turn is therefore folded into the *next* `"user"`
        turn's content (prefixed and clearly delimited) rather than dropped —
        so the attempt still executes and is still logged, but this is a real
        constraint of the target's API surface, not an adapter shortcut. Note
        it in THREAT_MODEL.md under identity/role exploitation: any
        system-prompt-override attack must ride in through the user-message
        or document-upload channel instead of a dedicated system channel.
    """
    if not patient_id:
        raise TargetError("patient_id is required — every /chat call is scoped to one patient")
    if not any(m["role"] == "user" for m in messages):
        raise TargetError("input_sequence must contain at least one 'user' turn")

    owns_client = client is None
    http = client or httpx.Client(base_url=base_url or TARGET_BASE_URL, timeout=TARGET_TIMEOUT_S)

    conversation_id = session_id
    transcript: list[TranscriptTurn] = []
    raw_responses: list[dict[str, Any]] = []
    total_tokens = 0
    total_usd = 0.0
    pending_document: dict[str, str] | None = None
    pending_prefix: str | None = None
    out_turn = 0

    try:
        for m in sorted(messages, key=lambda m: m["turn"]):
            role = m["role"]
            content = m["content"]

            if role == "uploaded_content":
                doc_type = m.get("doc_type")
                if not doc_type:
                    raise TargetError(f"turn {m['turn']}: 'uploaded_content' requires 'doc_type'")
                file_path = Path(content)
                if not file_path.is_file():
                    raise TargetError(f"turn {m['turn']}: document not found at '{content}'")
                resp = http.post(
                    "/documents/upload",
                    files={"file": (file_path.name, file_path.read_bytes())},
                    data={"doc_type": doc_type},
                )
                if resp.status_code >= 400:
                    raise TargetError(f"upload failed ({resp.status_code}): {resp.text[:500]}")
                pending_document = {
                    "document_path": resp.json()["document_path"],
                    "document_type": doc_type,
                }
                continue

            if role == "system_context":
                pending_prefix = f"[SYSTEM CONTEXT INJECTED]\n{content}"
                continue

            # role == "user"
            if pending_prefix:
                content = f"{pending_prefix}\n\n{content}"
                pending_prefix = None

            payload: dict[str, Any] = {"patient_id": patient_id, "message": content}
            if pending_document:
                payload.update(pending_document)
                pending_document = None
            if conversation_id:
                payload["conversation_id"] = conversation_id

            resp = http.post("/chat", json=payload)
            if resp.status_code >= 400:
                raise TargetError(f"chat failed ({resp.status_code}): {resp.text[:500]}")
            data = resp.json()
            raw_responses.append(data)
            conversation_id = data["conversation_id"]

            out_turn += 1
            transcript.append(TranscriptTurn(turn=out_turn, role="assistant", content=data["answer"]))

            stats = data.get("stats") or {}
            total_tokens += int(stats.get("input_tokens", 0)) + int(stats.get("output_tokens", 0))
            total_usd += float(stats.get("cost_usd", 0.0))
    finally:
        if owns_client:
            http.close()

    return TargetResult(
        session_id=conversation_id or session_id or str(uuid.uuid4()),
        target_transcript=transcript,
        cost={"tokens": total_tokens, "usd": round(total_usd, 6)},
        raw_responses=raw_responses,
    )
