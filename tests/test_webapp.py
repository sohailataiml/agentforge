"""Tests for the AgentForge Console web app (non-live).

Uses FastAPI's TestClient to verify the app boots, renders the console page,
reports config, and — critically — that the operator-token gate protects the
paid action endpoints. None of these trigger a live run: the token-gate tests
short-circuit with 401 before any network call, and the read endpoints only
touch local run logs.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

import agentforge.webapp as webapp  # noqa: E402


@pytest.fixture
def client() -> TestClient:
    return TestClient(webapp.app)


def test_index_renders_console(client: TestClient):
    resp = client.get("/")
    assert resp.status_code == 200
    assert "AgentForge" in resp.text
    assert "Run attack suite" in resp.text


def test_config_reports_capabilities(client: TestClient):
    cfg = client.get("/api/config").json()
    assert cfg["target_url"].startswith("http")
    assert set(cfg) >= {"judge_configured", "red_team_configured", "token_required", "categories"}
    assert "prompt_injection" in cfg["categories"]


def test_console_body_and_run_status(client: TestClient):
    assert client.get("/api/console-body").status_code == 200
    assert client.get("/api/run/status").json()["status"] in {"idle", "running", "done", "error"}


def test_actions_require_token_when_set(client: TestClient, monkeypatch):
    # With CONSOLE_TOKEN set, the paid endpoints must 401 before any network call.
    monkeypatch.setattr(webapp, "CONSOLE_TOKEN", "s3cret")
    assert client.post("/api/run").status_code == 401
    assert client.post("/api/run", headers={"X-Console-Token": "wrong"}).status_code == 401
    assert client.post("/api/redteam").status_code == 401


def test_redteam_without_key_is_clear_error(client: TestClient, monkeypatch):
    # No token gate (unset) + no Groq key -> a clean 400, not a crash.
    monkeypatch.setattr(webapp, "CONSOLE_TOKEN", None)
    monkeypatch.setattr(webapp, "red_team_configured", lambda: False)
    resp = client.post("/api/redteam")
    assert resp.status_code == 400
    assert "GROQ_API_KEY" in resp.json()["detail"]
