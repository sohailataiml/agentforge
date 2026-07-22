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


def test_prepared_directives_expose_expected_fields(client: TestClient):
    dirs = client.get("/api/directives").json()["directives"]
    d = next(x for x in dirs if x["id"] == "cross-patient-boundary")
    assert d["attack_category"] == "data_exfiltration"
    assert d["subcategory"] == "a synthetic cross-patient boundary test"
    assert d["strategy"] == "novel"
    assert d["patient_id"] and d["token_budget"] and d["max_turns"]  # synthetic id + small budget + short turns


def test_eval_cases_info_lists_the_suite(client: TestClient):
    cases = client.get("/api/cases").json()["cases"]
    assert len(cases) >= 3
    c = cases[0]
    assert {"case_id", "category", "subcategory", "invariant", "expected_result"} <= set(c)


def test_clear_requires_token_when_set(client: TestClient, monkeypatch):
    monkeypatch.setattr(webapp, "CONSOLE_TOKEN", "s3cret")
    assert client.post("/api/clear").status_code == 401


def test_clear_archives_run_logs(client: TestClient, tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "CONSOLE_TOKEN", None)
    monkeypatch.setattr(webapp, "_RESULTS_DIR", tmp_path)
    (tmp_path / "run-20260101T000000Z.jsonl").write_text('{"x":1}', encoding="utf-8")
    resp = client.post("/api/clear")
    assert resp.status_code == 200 and resp.json()["cleared"] == 1
    assert not list(tmp_path.glob("run-*.jsonl"))                       # moved out of the results view
    assert (tmp_path / "archive" / "run-20260101T000000Z.jsonl").exists()  # recoverable, not deleted


def test_redteam_rejects_unknown_directive(client: TestClient, monkeypatch):
    monkeypatch.setattr(webapp, "CONSOLE_TOKEN", None)
    monkeypatch.setattr(webapp, "red_team_configured", lambda: True)
    resp = client.post("/api/redteam", params={"directive_id": "does-not-exist"})
    assert resp.status_code == 400
    assert "unknown directive" in resp.json()["detail"]


def test_redteam_provider_failure_returns_json_not_500(client: TestClient, monkeypatch):
    # A provider failure (e.g. OpenRouter 429 after Groq refused) must surface as a
    # clean JSON 502 — not a raw 500 whose plain-text body breaks the frontend's .json().
    monkeypatch.setattr(webapp, "CONSOLE_TOKEN", None)
    monkeypatch.setattr(webapp, "red_team_configured", lambda: True)

    def boom(*a, **k):
        raise webapp.RedTeamError("provider error 429 (openrouter.ai)")

    monkeypatch.setattr(webapp, "run_directive", boom)
    resp = client.post("/api/redteam", params={"category": "data_exfiltration", "hostile": "true"})
    assert resp.status_code == 502
    body = resp.json()  # must be valid JSON
    assert "attack generation failed" in body["detail"] and "429" in body["detail"]


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
