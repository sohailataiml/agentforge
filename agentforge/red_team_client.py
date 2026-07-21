"""The one seam the Red Team Agent uses to reach its attack-generation model.

Mirrors the target-adapter philosophy: every Red Team generation goes through a
single, provider-agnostic function so the attacker model is swappable by config,
never by code. It speaks the OpenAI-compatible `/chat/completions` wire format,
which Groq, OpenRouter, and OpenAI all share — so switching providers (e.g. Groq
free tier -> an OpenRouter uncensored model when the safety-tuned default starts
refusing offensive-security generation) is an env-var change:

    RED_TEAM_BASE_URL   default https://api.groq.com/openai/v1   (Groq)
    RED_TEAM_MODEL      default llama-3.3-70b-versatile
    RED_TEAM_API_KEY    (or GROQ_API_KEY) — the provider key

The attacker model is deliberately a *different vendor from the Judge* (Anthropic
Opus) — the architecture's generator != judge independence rule — and open /
cheap because the Red Team is the highest-volume caller. Its output is untrusted:
this seam only *produces* text; nothing here executes it.

Uses httpx (already a dependency) rather than a provider SDK to stay
dependency-light and to keep one code path across providers.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import httpx

# Groq free tier is the default: fastest inference, no card to start, different
# vendor from the Anthropic Judge. Swap these for OpenRouter to reach an
# uncensored open-weight model with no code change.
RED_TEAM_BASE_URL = os.environ.get("RED_TEAM_BASE_URL", "https://api.groq.com/openai/v1")
RED_TEAM_MODEL = os.environ.get("RED_TEAM_MODEL", "llama-3.3-70b-versatile")
RED_TEAM_TIMEOUT_S = float(os.environ.get("RED_TEAM_TIMEOUT_S", "60"))


class RedTeamError(RuntimeError):
    """No provider key configured, or the provider was unreachable / errored."""


@dataclass
class Completion:
    """One attack-generation response and the cost of producing it."""

    text: str
    cost: dict[str, Any]  # {"tokens": int, "usd": float} — shape matches contracts
    model: str
    raw: dict[str, Any] = field(default_factory=dict)


def resolve_api_key(api_key: str | None = None) -> str | None:
    """Provider key resolution: explicit arg -> RED_TEAM_API_KEY -> GROQ_API_KEY.

    Returns None when nothing is configured so callers can surface a clear setup
    message instead of sending an unauthenticated request.
    """
    return api_key or os.environ.get("RED_TEAM_API_KEY") or os.environ.get("GROQ_API_KEY")


def red_team_configured() -> bool:
    """Whether a provider key is available — lets the CLI skip live Red Team work
    with a clear message instead of failing mid-campaign."""
    return resolve_api_key() is not None


def _cost(usage: dict[str, Any]) -> dict[str, Any]:
    # Open-model pricing varies by provider (Groq's free tier is $0). Read at call
    # time so a paid endpoint's per-1M-token rates can be set via env without a
    # module reload. USD per 1M tokens.
    per_in = float(os.environ.get("RED_TEAM_USD_PER_1M_INPUT", "0"))
    per_out = float(os.environ.get("RED_TEAM_USD_PER_1M_OUTPUT", "0"))
    prompt = int(usage.get("prompt_tokens", 0) or 0)
    completion = int(usage.get("completion_tokens", 0) or 0)
    total = int(usage.get("total_tokens", 0) or (prompt + completion))
    usd = prompt * per_in / 1_000_000 + completion * per_out / 1_000_000
    return {"tokens": total, "usd": round(usd, 6)}


def complete(
    messages: list[dict[str, Any]],
    *,
    temperature: float = 0.9,  # high by default — attack variety over determinism
    max_tokens: int = 1024,
    model: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
    client: httpx.Client | None = None,
) -> Completion:
    """Generate one completion from the Red Team's model via any OpenAI-compatible
    provider.

    Args:
        messages: OpenAI-style chat messages ([{role, content}, ...]) — typically a
            system prompt framing the model as an authorized red-team tester plus
            the AttackDirective as the user turn.
        temperature: sampling temperature; high (0.9) by default so a mutation loop
            gets varied attacks rather than the same phrasing each call.
        model / base_url / api_key: per-call overrides of the env defaults (mainly
            for tests and for switching Groq <-> OpenRouter).
        client: reuse an httpx.Client (shared pooling across a campaign, or a
            MockTransport client in tests). Owned/closed internally when omitted.

    Raises:
        RedTeamError: no provider key configured, the request failed, or the
            response was malformed.
    """
    key = resolve_api_key(api_key)
    if not key:
        raise RedTeamError(
            "no Red Team provider key — set GROQ_API_KEY (or RED_TEAM_API_KEY). "
            "Sign up at console.groq.com for a free key."
        )
    if not messages:
        raise RedTeamError("messages must be non-empty")

    base = (base_url or RED_TEAM_BASE_URL).rstrip("/")
    payload = {
        "model": model or RED_TEAM_MODEL,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    owns_client = client is None
    http = client or httpx.Client(timeout=RED_TEAM_TIMEOUT_S)
    try:
        resp = http.post(f"{base}/chat/completions", json=payload, headers=headers)
    except httpx.HTTPError as exc:
        raise RedTeamError(f"Red Team provider unreachable: {exc}") from exc
    finally:
        if owns_client:
            http.close()

    if resp.status_code >= 400:
        raise RedTeamError(f"Red Team provider error ({resp.status_code}): {resp.text[:500]}")
    try:
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        raise RedTeamError(f"malformed provider response: {exc}") from exc

    return Completion(
        text=text or "",
        cost=_cost(data.get("usage") or {}),
        model=data.get("model", payload["model"]),
        raw=data,
    )
