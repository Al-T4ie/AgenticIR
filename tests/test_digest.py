"""The ten-minute catch-up, and the discipline that keeps it readable.

A digest is easy to build and easy to make worthless. The two ways it goes
wrong are posting when there is nothing to say — which trains everyone to skip
it, so it is not there when it matters — and restating the whole incident every
time instead of what changed. Both are pinned down here.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.slack import digest


def _at(minutes_ago: int) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes_ago)).isoformat()


def record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "INC-1",
        "status": "running",
        "mode": "winger",
        "severity": "high",
        "verdict": "true_positive",
        "confidence": 0.72,
        "findings": [{"title": "a"}, {"title": "b"}],
        "containment_actions": [],
        "open_questions": [],
        "pending_notes": [],
        "timeline": [],
        "created_at": _at(70),
        "updated_at": _at(1),
        "last_digest_at": _at(10),
    }
    base.update(overrides)
    return base


def text_of(built: dict[str, Any]) -> str:
    return "\n".join(
        block.get("text", {}).get("text", "")
        or " ".join(e.get("text", "") for e in block.get("elements", []))
        for block in built["blocks"]
    )


def test_a_quiet_incident_with_nothing_stuck_says_nothing() -> None:
    """Ten minutes of 'no change' every ten minutes is how a channel gets muted."""
    assert digest.compose(record())["post"] is False


def test_only_what_happened_since_the_last_one_is_reported() -> None:
    built = digest.compose(
        record(
            timeline=[
                {"at": _at(60), "actor": "intake", "event": "Incident opened"},
                {"at": _at(45), "actor": "triage", "event": "Reported 4 finding(s)"},
                {"at": _at(4), "actor": "behavioral", "event": "Reported 6 finding(s)"},
            ]
        )
    )
    body = text_of(built)
    assert "behavioral" in body
    assert "Incident opened" not in body, "the window starts at the previous digest"
    assert built["events"] == 1


def test_repeated_updates_from_one_agent_collapse_to_the_latest() -> None:
    built = digest.compose(
        record(
            timeline=[
                {"at": _at(8), "actor": "supervisor", "event": "Round 1: dispatched triage"},
                {"at": _at(3), "actor": "supervisor", "event": "Round 2: dispatched behavioral"},
            ]
        )
    )
    body = text_of(built)
    assert "Round 2" in body
    assert "+1 more" in body


def test_an_unapproved_plan_is_reported_every_time_with_how_long_it_has_waited() -> None:
    """The most useful sentence the message can contain, and the one that stops
    being useful if it is said once and never again."""
    built = digest.compose(
        record(
            status="awaiting_approval",
            containment_actions=[
                {
                    "action": "revoke_oauth_token",
                    "target": "app:Migrator",
                    "requires_approval": True,
                }
            ],
            timeline=[
                {"at": _at(95), "actor": "containment_planner", "event": "Proposed 1 action(s)"}
            ],
        )
    )
    body = text_of(built)
    assert built["post"] is True
    assert "waiting on approval" in body
    assert "1h 35m" in body
    assert "revoke_oauth_token" in body


def test_unanswered_questions_keep_the_digest_alive_on_a_silent_incident() -> None:
    built = digest.compose(record(open_questions=["Is the Migrator app expected to bulk-export?"]))
    assert built["post"] is True
    assert "unanswered" in text_of(built)


def test_queued_notes_are_declared_so_nobody_thinks_they_were_dropped() -> None:
    built = digest.compose(
        record(
            open_questions=["anything?"],
            pending_notes=[{"note": "x"}, {"note": "y"}],
        )
    )
    assert "2 note(s) queued" in text_of(built)


def test_a_spectator_says_plainly_that_it_will_do_nothing() -> None:
    """A bot doing nothing on purpose and a bot that has stalled look identical
    from the outside until one of them acts."""
    built = digest.compose(record(mode="spectator", open_questions=["q"]))
    assert "spectator mode" in text_of(built)


def test_a_gated_incident_says_new_information_will_supersede_the_plan() -> None:
    built = digest.compose(
        record(
            status="awaiting_approval",
            containment_actions=[{"action": "isolate_host", "requires_approval": True}],
        )
    )
    assert "supersede" in text_of(built)


def test_the_first_digest_covers_everything_back_to_the_alert() -> None:
    built = digest.compose(
        record(
            last_digest_at=None,
            created_at=_at(20),
            timeline=[{"at": _at(15), "actor": "triage", "event": "Reported 4 finding(s)"}],
        )
    )
    assert built["events"] == 1


def test_the_standing_position_is_always_shown() -> None:
    built = digest.compose(
        record(timeline=[{"at": _at(2), "actor": "critic", "event": "Review: true_positive"}])
    )
    body = text_of(built)
    assert "true positive" in body
    assert "high" in body
    assert "72%" in body
    assert "2 finding(s)" in body


def test_a_flood_of_actors_is_truncated_rather_than_flooding_the_channel() -> None:
    built = digest.compose(
        record(
            timeline=[
                {"at": _at(2), "actor": f"agent{i}", "event": f"did thing {i}"} for i in range(12)
            ]
        )
    )
    body = text_of(built)
    assert "other actor(s)" in body
    assert len(body) < 2900


def test_the_message_never_exceeds_what_slack_will_render() -> None:
    built = digest.compose(
        record(
            open_questions=["x" * 900, "y" * 900, "z" * 900],
            timeline=[{"at": _at(2), "actor": "triage", "event": "q" * 4000}],
        )
    )
    for block in built["blocks"]:
        if block["type"] == "section":
            assert len(block["text"]["text"]) <= 2900


async def test_posting_without_a_channel_is_a_no_op(monkeypatch) -> None:
    from types import SimpleNamespace

    monkeypatch.setattr(digest, "get_settings", lambda: SimpleNamespace(slack_enabled=True))
    assert await digest.post(record(slack_channel="")) is False


async def test_a_war_room_digest_goes_to_the_room_not_a_thread(monkeypatch) -> None:
    from types import SimpleNamespace

    sent: list[dict[str, Any]] = []

    async def _post(channel: str, *, text: str, blocks_payload=None, thread_ts: str = "") -> str:
        sent.append({"channel": channel, "thread_ts": thread_ts})
        return "1.0"

    monkeypatch.setattr(digest, "get_settings", lambda: SimpleNamespace(slack_enabled=True))
    monkeypatch.setattr("app.slack.notifier.post", _post)

    assert await digest.post(
        record(slack_channel="C_ROOM", slack_thread_ts="", open_questions=["q"])
    )
    assert sent == [{"channel": "C_ROOM", "thread_ts": ""}]


async def test_a_slack_failure_never_escapes(monkeypatch) -> None:
    from types import SimpleNamespace

    async def _boom(*_a: Any, **_k: Any) -> str:
        raise RuntimeError("ratelimited")

    monkeypatch.setattr(digest, "get_settings", lambda: SimpleNamespace(slack_enabled=True))
    monkeypatch.setattr("app.slack.notifier.post", _boom)

    assert await digest.post(record(slack_channel="C1", open_questions=["q"])) is False
