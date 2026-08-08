"""API surface: authentication, validation, and webhook intake."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

API_KEY = "test-api-key"


@pytest.fixture
def client() -> TestClient:
    # No context manager: the lifespan (database, checkpointer) is deliberately
    # not run, so these tests stay hermetic.
    return TestClient(create_app())


# ── Health ───────────────────────────────────────────────────────────────────
def test_health_needs_no_auth(client: TestClient):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_ready_reports_503_before_startup(client: TestClient):
    assert client.get("/ready").status_code == 503


def test_metrics_exposed(client: TestClient):
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "agenticir_runs_started_total" in resp.text


def test_root_redirects_to_ui(client: TestClient):
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 307
    assert resp.headers["location"] == "/ui"


# ── Authentication ───────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    "path",
    ["/v1/incidents", "/v1/incidents/INC-1", "/v1/incidents/INC-1/state"],
)
def test_v1_requires_api_key(client: TestClient, path: str):
    assert client.get(path).status_code == 401


def test_v1_rejects_wrong_api_key(client: TestClient):
    resp = client.get("/v1/incidents", headers={"X-API-Key": "nope"})
    assert resp.status_code == 401


def test_webhook_requires_bearer_token(client: TestClient):
    assert client.post("/webhooks/alert", json={"title": "x"}).status_code == 401


def test_webhook_rejects_wrong_bearer(client: TestClient):
    resp = client.post(
        "/webhooks/alert", json={"title": "x"}, headers={"Authorization": "Bearer wrong"}
    )
    assert resp.status_code == 401


def test_ui_redirects_to_login_when_unauthenticated(client: TestClient):
    resp = client.get("/ui", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/ui/login"


def test_ui_login_rejects_bad_key(client: TestClient):
    resp = client.post("/ui/login", data={"api_key": "wrong"}, follow_redirects=False)
    assert resp.status_code == 303
    assert "error" in resp.headers["location"]


def test_ui_login_sets_httponly_cookie(client: TestClient):
    resp = client.post("/ui/login", data={"api_key": API_KEY}, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/ui"
    cookie = resp.headers.get("set-cookie", "")
    assert "agenticir_key=" in cookie
    assert "HttpOnly" in cookie


# ── Validation & intake ──────────────────────────────────────────────────────
def test_create_investigation_rejects_empty_payload(client: TestClient):
    resp = client.post("/v1/incidents", headers={"X-API-Key": API_KEY}, json={})
    assert resp.status_code == 422


def test_create_investigation_starts_a_run(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    started: dict[str, Any] = {}

    async def fake_start(**kwargs: Any) -> dict[str, Any]:
        started.update(kwargs)
        return {"id": "INC-TEST-1", "thread_id": "INC-TEST-1", "title": "t"}

    monkeypatch.setattr("app.api.routes.runner.start_investigation", fake_start)

    resp = client.post(
        "/v1/incidents",
        headers={"X-API-Key": API_KEY},
        json={"alert": {"title": "Beaconing host"}, "source": "api"},
    )
    assert resp.status_code == 202
    assert resp.json()["incident_id"] == "INC-TEST-1"
    assert started["alert"] == {"title": "Beaconing host"}


def test_webhook_unwraps_nested_alert(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    seen: dict[str, Any] = {}

    async def fake_start(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"id": "INC-2", "thread_id": "INC-2", "title": "t"}

    monkeypatch.setattr("app.api.routes.runner.start_investigation", fake_start)

    resp = client.post(
        "/webhooks/alert",
        headers={"Authorization": f"Bearer {API_KEY}"},
        json={"alert": {"title": "wrapped"}, "source": "splunk"},
    )
    assert resp.status_code == 202
    assert seen["alert"] == {"title": "wrapped"}
    assert seen["source"] == "splunk"


def test_webhook_accepts_a_bare_siem_body(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    """A SIEM posting its native shape must work without an n8n transform."""
    seen: dict[str, Any] = {}

    async def fake_start(**kwargs: Any) -> dict[str, Any]:
        seen.update(kwargs)
        return {"id": "INC-3", "thread_id": "INC-3", "title": "t"}

    monkeypatch.setattr("app.api.routes.runner.start_investigation", fake_start)

    body = {"rule_name": "Impossible travel", "severity": "high", "user": "a.smith"}
    resp = client.post("/webhooks/alert", headers={"Authorization": f"Bearer {API_KEY}"}, json=body)
    assert resp.status_code == 202
    assert seen["alert"] == body


def test_missing_incident_returns_404(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    async def none_incident(_: str) -> None:
        return None

    monkeypatch.setattr("app.api.routes.incidents.get_incident", none_incident)
    resp = client.get("/v1/incidents/INC-nope", headers={"X-API-Key": API_KEY})
    assert resp.status_code == 404
