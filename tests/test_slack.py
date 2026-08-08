"""Slack signature verification and Block Kit construction."""

from __future__ import annotations

import hashlib
import hmac
import time

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.slack import blocks
from app.slack.handlers import clean_text
from app.slack.verify import verify_slack_request

SECRET = "test-signing-secret"


def sign(body: bytes, timestamp: str | None = None, secret: str = SECRET) -> tuple[str, str]:
    ts = timestamp or str(int(time.time()))
    base = b"v0:" + ts.encode() + b":" + body
    sig = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return ts, sig


# ── Signature verification ───────────────────────────────────────────────────
def test_valid_signature_accepted():
    body = b'{"type":"event_callback"}'
    ts, sig = sign(body)
    assert verify_slack_request(body, ts, sig) is True


def test_tampered_body_rejected():
    body = b'{"type":"event_callback"}'
    ts, sig = sign(body)
    assert verify_slack_request(b'{"type":"evil"}', ts, sig) is False


def test_wrong_secret_rejected():
    body = b"{}"
    ts, sig = sign(body, secret="attacker-secret")
    assert verify_slack_request(body, ts, sig) is False


def test_replayed_old_request_rejected():
    body = b"{}"
    old = str(int(time.time()) - 600)  # 10 minutes ago
    ts, sig = sign(body, timestamp=old)
    assert verify_slack_request(body, ts, sig) is False


@pytest.mark.parametrize(
    ("ts", "sig"),
    [(None, "v0=abc"), ("123", None), (None, None), ("not-a-number", "v0=abc")],
)
def test_malformed_headers_rejected(ts: str | None, sig: str | None):
    assert verify_slack_request(b"{}", ts, sig) is False


# ── Endpoint behaviour ───────────────────────────────────────────────────────
def test_url_verification_challenge_echoed():
    client = TestClient(create_app())
    body = b'{"type":"url_verification","challenge":"abc123xyz"}'
    ts, sig = sign(body)
    resp = client.post(
        "/slack/events",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Slack-Request-Timestamp": ts,
            "X-Slack-Signature": sig,
        },
    )
    assert resp.status_code == 200
    assert resp.text == "abc123xyz"


def test_unsigned_event_rejected():
    client = TestClient(create_app())
    resp = client.post("/slack/events", json={"type": "event_callback"})
    assert resp.status_code == 401


def test_unsigned_interaction_rejected():
    client = TestClient(create_app())
    resp = client.post("/slack/interactions", data={"payload": "{}"})
    assert resp.status_code == 401


# ── Text normalisation ───────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("<@U012ABC> investigate this", "investigate this"),
        ("<@U012ABC>   spaced   ", "spaced"),
        ("check <https://evil.test/path>", "check evil.test/path"),
        ("mail <mailto:a@b.com|a@b.com>", "mail a@b.com"),
        ("no mention here", "no mention here"),
        ("", ""),
    ],
)
def test_clean_text(raw: str, expected: str):
    assert clean_text(raw) == expected


# ── Block Kit ────────────────────────────────────────────────────────────────
def test_report_blocks_stay_within_slack_limits():
    incident = {
        "id": "INC-1",
        "severity": "critical",
        "verdict": "true_positive",
        "confidence": 0.91,
        "findings": [{"title": "f"} for _ in range(5)],
        "report": "A" * 12000,  # well past Slack's 3000-char text limit
        "containment_actions": [
            {"action": "isolate_host", "target": "H1", "requires_approval": True}
        ],
    }
    built = blocks.report_message(incident, "https://app.example.com")

    for block in built:
        if block.get("type") == "section":
            assert len(block["text"]["text"]) <= 3000
        if block.get("type") == "header":
            assert len(block["text"]["text"]) <= 150

    assert any(b.get("type") == "actions" for b in built), "dashboard link should be present"


def test_approval_blocks_carry_incident_id_and_confirmation():
    payload = {
        "severity": "high",
        "verdict": "true_positive",
        "summary": "Confirmed beaconing.",
        "actions": [
            {
                "action": "isolate_host",
                "target": "FIN-WS-04",
                "justification": "C2 confirmed",
                "risk": "high",
                "reversible": False,
            }
        ],
    }
    built = blocks.approval_request("INC-42", payload)

    actions = next(b for b in built if b["type"] == "actions")
    assert actions["block_id"] == "approval::INC-42"

    ids = {e["action_id"] for e in actions["elements"]}
    assert ids == {"approve_all", "reject_all"}

    approve = next(e for e in actions["elements"] if e["action_id"] == "approve_all")
    assert approve["value"] == "INC-42"
    # Executing containment against production must not be a single misclick.
    assert "confirm" in approve

    rendered = " ".join(b["text"]["text"] for b in built if b.get("type") == "section")
    assert "not reversible" in rendered


def test_report_blocks_handle_a_missing_report():
    built = blocks.report_message(
        {"id": "INC-9", "severity": "low", "verdict": "false_positive", "confidence": 0.4}
    )
    assert built
    assert any("No report produced" in b.get("text", {}).get("text", "") for b in built)
