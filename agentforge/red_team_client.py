"""The one seam the Red Team Agent uses to reach its attack-generation model.

Mirrors the target-adapter philosophy: every Red Team generation goes through a
single, provider-agnostic function so the attacker model is swappable by config,
never by code. It speaks the OpenAI-compatible `/chat/completions` wire format,
which Groq, OpenRouter, and OpenAI all share.

    RED_TEAM_BASE_URL   default https://api.groq.com/openai/v1   (Groq, primary)
    RED_TEAM_MODEL      default llama-3.3-70b-versatile
    RED_TEAM_API_KEY    (or GROQ_API_KEY) — the primary provider key

**Automatic fallback.** The primary is a cheap, fast, but *safety-tuned* open
model (Groq/Llama). When it refuses to generate an offensive-security attack — or
is unreachable/errors — `complete()` automatically retries on an uncensored
fallback provider (OpenRouter by default) so the campaign is not blocked by the
attacker model's own guardrails. This is the runtime realization of the "open /
uncensored model for offensive workflows" model-tiering decision.

    RED_TEAM_FALLBACK_BASE_URL   default https://openrouter.ai/api/v1
    RED_TEAM_FALLBACK_MODEL      default cognitivecomputations/dolphin-mistral-24b-venice-edition
    RED_TEAM_FALLBACK_API_KEY    (or OPENROUTER_API_KEY)

The attacker model is deliberately a *different vendor from the Judge* (Anthropic
Opus) — the architecture's generator != judge independence rule. Its output is
untrusted: this seam only *produces* text; nothing here executes it.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

# Retry transient provider failures (esp. OpenRouter/Venice 429 rate-limit spikes)
# before giving up. _RETRY_BASE_S is module-level so tests can zero it out.
_RETRY_STATUS = (429, 500, 502, 503, 504)
_RETRY_ATTEMPTS = 3
_RETRY_BASE_S = 0.8

# Primary provider — Groq free tier: fastest, no card, different vendor from the Judge.
RED_TEAM_BASE_URL = os.environ.get("RED_TEAM_BASE_URL", "https://api.groq.com/openai/v1")
RED_TEAM_MODEL = os.environ.get("RED_TEAM_MODEL", "llama-3.3-70b-versatile")
RED_TEAM_TIMEOUT_S = float(os.environ.get("RED_TEAM_TIMEOUT_S", "60"))

# Fallback provider — an uncensored open-weight model reached when the primary
# refuses or errors. Defaults to an OpenRouter Dolphin (Venice) model.
RED_TEAM_FALLBACK_BASE_URL = os.environ.get("RED_TEAM_FALLBACK_BASE_URL", "https://openrouter.ai/api/v1")
RED_TEAM_FALLBACK_MODEL = os.environ.get(
    "RED_TEAM_FALLBACK_MODEL", "cognitivecomputations/dolphin-mistral-24b-venice-edition"
)

# Openings that mark the attacker model declining to generate the attack. Checked
# against the start of the response so a valid JSON attack payload can't match.
_REFUSAL_MARKERS = (
    "i can't", "i cannot", "i can not", "i won't", "i will not", "i'm sorry",
    "i am sorry", "i'm not able", "i am not able", "i'm unable", "i am unable",
    "as an ai", "i must decline", "i'm not going to", "i am not going to",
    "i do not feel comfortable", "i'm not comfortable", "i apologize", "i refuse",
    "i'm really sorry", "sorry, but", "i won't be able", "i can't help",
    "i cannot assist", "i can't assist", "i'm not willing",
)


class RedTeamError(RuntimeError):
    """No provider key configured, or the provider was unreachable / errored."""


@dataclass
class Completion:
    """One attack-generation response and the cost/provenance of producing it."""

    text: str
    cost: dict[str, Any]  # {"tokens": int, "usd": float} — shape matches contracts
    model: str
    served_by: str = ""  # base URL of the provider that actually produced this
    fell_back: bool = False  # True if the primary refused/errored and the fallback served
    fallback_reason: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


def resolve_api_key(api_key: str | None = None) -> str | None:
    """Primary key: explicit arg -> RED_TEAM_API_KEY -> GROQ_API_KEY."""
    return api_key or os.environ.get("RED_TEAM_API_KEY") or os.environ.get("GROQ_API_KEY")


def resolve_fallback_key() -> str | None:
    """Fallback key: RED_TEAM_FALLBACK_API_KEY -> OPENROUTER_API_KEY."""
    return os.environ.get("RED_TEAM_FALLBACK_API_KEY") or os.environ.get("OPENROUTER_API_KEY")


def red_team_configured() -> bool:
    """Whether a primary provider key is available."""
    return resolve_api_key() is not None


def fallback_configured() -> bool:
    """Whether an uncensored fallback provider is available."""
    return resolve_fallback_key() is not None


def is_refusal(text: str) -> bool:
    """Heuristic: did the attacker model decline instead of producing an attack?

    A valid attack is a JSON object/array, so anything starting with `{`/`[` is
    never a refusal; otherwise a refusal opener near the start counts.
    """
    s = (text or "").strip()
    if not s or s[0] in "{[":
        return False
    head = s.lower()[:280]
    return any(marker in head for marker in _REFUSAL_MARKERS)


def _cost(usage: dict[str, Any]) -> dict[str, Any]:
    # Open-model pricing varies by provider (Groq's free tier is $0). Read at call
    # time so a paid endpoint's per-1M-token rates can be set via env. USD per 1M.
    per_in = float(os.environ.get("RED_TEAM_USD_PER_1M_INPUT", "0"))
    per_out = float(os.environ.get("RED_TEAM_USD_PER_1M_OUTPUT", "0"))
    prompt = int(usage.get("prompt_tokens", 0) or 0)
    completion = int(usage.get("completion_tokens", 0) or 0)
    total = int(usage.get("total_tokens", 0) or (prompt + completion))
    usd = prompt * per_in / 1_000_000 + completion * per_out / 1_000_000
    return {"tokens": total, "usd": round(usd, 6)}


def _call_provider(
    messages: list[dict[str, Any]],
    *,
    temperature: float,
    max_tokens: int,
    model: str,
    base_url: str,
    api_key: str,
    client: httpx.Client | None,
) -> Completion:
    """One OpenAI-compatible /chat/completions call to a single provider.

    Raises RedTeamError on transport failure, non-2xx, or a malformed body.
    """
    base = base_url.rstrip("/")
    payload = {"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    owns_client = client is None
    http = client or httpx.Client(timeout=RED_TEAM_TIMEOUT_S)
    resp = None
    last_exc: Exception | None = None
    try:
        for attempt in range(_RETRY_ATTEMPTS):
            try:
                resp = http.post(f"{base}/chat/completions", json=payload, headers=headers)
                last_exc = None
            except httpx.HTTPError as exc:
                resp, last_exc = None, exc
            if resp is not None and resp.status_code not in _RETRY_STATUS:
                break
            if attempt < _RETRY_ATTEMPTS - 1:
                delay = _RETRY_BASE_S * (attempt + 1)
                ra = (resp.headers.get("retry-after") if resp is not None else "") or ""
                if ra.replace(".", "", 1).isdigit():
                    delay = min(float(ra), 10.0)
                time.sleep(delay)
    finally:
        if owns_client:
            http.close()

    if resp is None:
        raise RedTeamError(f"provider unreachable ({base}): {last_exc}") from last_exc
    if resp.status_code >= 400:
        raise RedTeamError(f"provider error {resp.status_code} ({base}): {resp.text[:400]}")
    try:
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise RedTeamError(f"malformed provider response ({base}): {exc}") from exc

    return Completion(
        text=text or "",
        cost=_cost(data.get("usage") or {}),
        model=data.get("model", model),
        served_by=base,
        raw=data,
    )


def complete(
    messages: list[dict[str, Any]],
    *,
    temperature: float = 0.9,  # high by default — attack variety over determinism
    max_tokens: int = 1024,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    client: httpx.Client | None = None,
    allow_fallback: bool = True,
    detect_refusal: bool = True,
) -> Completion:
    """Generate one completion, automatically failing over to the uncensored
    fallback provider if the primary refuses or errors.

    Args:
        messages: OpenAI-style chat messages ([{role, content}, ...]).
        model / base_url / api_key: per-call overrides of the primary env defaults.
        client: reuse an httpx.Client (campaign pooling, or a MockTransport in tests).
        allow_fallback: set False to force single-provider behavior (e.g. to test
            the primary in isolation).
        detect_refusal: whether a refusal in the primary's text triggers fallback
            (provider errors always do, regardless of this flag).

    Raises:
        RedTeamError: no primary key configured, empty messages, or the primary
            failed and no fallback is configured (or the fallback also failed).
    """
    key = resolve_api_key(api_key)
    if not key:
        raise RedTeamError(
            "no Red Team provider key — set GROQ_API_KEY (or RED_TEAM_API_KEY). "
            "Sign up at console.groq.com for a free key."
        )
    if not messages:
        raise RedTeamError("messages must be non-empty")

    primary_base = base_url or RED_TEAM_BASE_URL
    primary_model = model or RED_TEAM_MODEL

    def _fallback(reason: str) -> Completion:
        fb = _call_provider(
            messages, temperature=temperature, max_tokens=max_tokens,
            model=RED_TEAM_FALLBACK_MODEL, base_url=RED_TEAM_FALLBACK_BASE_URL,
            api_key=resolve_fallback_key(), client=client,
        )
        fb.fell_back = True
        fb.fallback_reason = reason
        return fb

    can_fall_back = (
        allow_fallback
        and fallback_configured()
        and RED_TEAM_FALLBACK_BASE_URL.rstrip("/") != primary_base.rstrip("/")
    )

    try:
        result = _call_provider(
            messages, temperature=temperature, max_tokens=max_tokens,
            model=primary_model, base_url=primary_base, api_key=key, client=client,
        )
    except RedTeamError as exc:
        if can_fall_back:
            return _fallback(f"primary provider failed — {exc}")
        raise

    if can_fall_back and detect_refusal and is_refusal(result.text):
        return _fallback(f"primary model ({primary_model}) refused to generate the attack")
    return result
