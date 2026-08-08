"""Channel awareness: progress narration, the polling sweep, and revisions.

These stay hermetic — no database, no Slack, no model. What is being pinned
down is the decision logic: which messages the bot takes responsibility for,
what it refuses to act on, and where its replies land.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from app.slack import poller, progress


# ── Fixtures ─────────────────────────────────────────────────────────────────
@pytest.fixture
def slack_on(monkeypatch: pytest.MonkeyPatch):
    """Pretend Slack is configured, without touching real settings."""
    settings = SimpleNamespace(
        slack_enabled=True,
        slack_progress_updates=True,
        slack_poll_enabled=True,
        slack_poll_max_actions=3,
        slack_poll_lookback_minutes=60,
        slack_poll_thread_window_hours=24,
        slack_poll_report_decisions=True,
        polled_channels=["C_TEST"],
        slack_bot_token="xoxb-test",
    )
    monkeypatch.setattr(progress, "get_settings", lambda: settings)
    monkeypatch.setattr(poller, "get_settings", lambda: settings)
    return settings


@pytest.fixture
def posted(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture everything that would have been sent to Slack."""
    sent: list[dict[str, Any]] = []

    async def fake_post(channel, *, text, blocks_payload=None, thread_ts=""):
        sent.append({"channel": channel, "text": text, "thread_ts": thread_ts})
        return "1700000000.000100"

    from app.slack import notifier

    monkeypatch.setattr(notifier, "post", fake_post)
    return sent


def _incident(**overrides: Any) -> dict[str, Any]:
    base = {
        "id": "INC-1",
        "thread_id": "INC-1",
        "status": "completed",
        "severity": "high",
        "verdict": "true_positive",
        "title": "Encoded PowerShell",
        "slack_channel": "C_TEST",
        "slack_thread_ts": "1700000000.000001",
        "findings": [],
        "report": "",
        "summary": "",
    }
    base.update(overrides)
    return base


# ── Progress narration ───────────────────────────────────────────────────────
async def test_progress_posts_into_the_incident_thread(slack_on, posted, monkeypatch):
    progress.forget("INC-1")
    monkeypatch.setattr(progress.incidents, "get_incident", lambda _id: _async(_incident()))

    await progress.planning("INC-1", 1, ["triage", "enrichment"], "fresh alert")

    assert len(posted) == 1
    assert posted[0]["channel"] == "C_TEST"
    # Narration must stay in the thread, never land in the channel.
    assert posted[0]["thread_ts"] == "1700000000.000001"
    assert "triage" in posted[0]["text"]


async def test_progress_is_silent_without_a_thread(slack_on, posted, monkeypatch):
    """An incident from the API has no Slack thread; there is nowhere to narrate."""
    progress.forget("INC-1")
    monkeypatch.setattr(
        progress.incidents,
        "get_incident",
        lambda _id: _async(_incident(slack_channel="", slack_thread_ts="")),
    )

    await progress.reviewed("INC-1", "true_positive", "high", False, "")
    assert posted == []


async def test_progress_is_disabled_by_configuration(slack_on, posted, monkeypatch):
    slack_on.slack_progress_updates = False
    monkeypatch.setattr(progress.incidents, "get_incident", lambda _id: _async(_incident()))

    await progress.reviewed("INC-1", "true_positive", "high", False, "")
    assert posted == []


async def test_progress_never_raises(slack_on, monkeypatch):
    """A Slack outage mid-investigation must not fail the investigation."""
    progress.forget("INC-2")

    async def boom(_id):
        raise RuntimeError("database is on fire")

    monkeypatch.setattr(progress.incidents, "get_incident", boom)
    await progress.specialist_failed("INC-2", "triage", "timeout")  # must not raise


# ── Which messages the sweep will even look at ───────────────────────────────
@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ({"user": "U_HUMAN", "text": "look at this"}, True),
        ({"user": "U_SELF", "text": "my own report"}, False),
        ({"user": "U_HUMAN", "text": "x", "bot_id": "B1"}, False),
        ({"user": "U_HUMAN", "text": "x", "app_id": "A1"}, False),
        ({"user": "U_HUMAN", "text": "hi", "subtype": "channel_join"}, False),
        ({"user": "U_HUMAN", "text": "also in channel", "subtype": "thread_broadcast"}, True),
        ({"user": "U_HUMAN", "text": "   "}, False),
        ({"text": "no author"}, False),
    ],
)
def test_message_filter(message: dict[str, Any], expected: bool):
    assert poller._is_human_message(message, "U_SELF") is expected


async def test_channel_ids_pass_through_unresolved():
    assert await poller.resolve_channel("C0BNHCPQJPR") == "C0BNHCPQJPR"


# ── Classification ───────────────────────────────────────────────────────────
async def test_classifier_rejects_an_invented_incident_id(monkeypatch):
    """A hallucinated id would silently attach information to the wrong incident."""

    async def fake_structured(role, schema, messages):  # noqa: ARG001
        return poller.Triage(
            dispositions=[
                poller.Disposition(ts="1", action="update_incident", incident_id="INC-NOPE"),
                poller.Disposition(ts="2", action="update_incident", incident_id="INC-1"),
            ]
        )

    monkeypatch.setattr(poller.llm, "structured", fake_structured)

    out = await poller.classify(
        [
            {"ts": "1", "user": "U", "text": "a", "thread_ts": "", "incident_id": ""},
            {"ts": "2", "user": "U", "text": "b", "thread_ts": "", "incident_id": ""},
        ],
        [_incident()],
    )

    assert "1" not in out
    assert out["2"].incident_id == "INC-1"


async def test_a_failed_classifier_acts_on_nothing(monkeypatch):
    async def boom(role, schema, messages):  # noqa: ARG001
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(poller.llm, "structured", boom)
    assert (
        await poller.classify(
            [{"ts": "1", "user": "U", "text": "x", "thread_ts": "", "incident_id": ""}], []
        )
        == {}
    )


# ── Acting on a disposition ──────────────────────────────────────────────────
async def test_new_information_reopens_the_incident_in_its_own_thread(
    slack_on, posted, monkeypatch
):
    calls: list[tuple[str, str]] = []

    async def fake_follow_up(incident_id, note, *, reported_by=""):
        calls.append((incident_id, note))
        return "revising"

    monkeypatch.setattr(poller.runner, "follow_up_investigation", fake_follow_up)
    monkeypatch.setattr(poller.incidents, "get_incident", lambda _id: _async(_incident()))
    monkeypatch.setattr(poller.slack_watch, "release", _noop)

    result = await poller._act(
        "C_TEST",
        {
            "ts": "1700000009.000000",
            "user": "U_HUMAN",
            "text": "FIN-WS-04 is our Jenkins agent, that PowerShell is a build step",
            "thread_ts": "",
            "incident_id": "INC-1",
        },
        "update_incident",
        "INC-1",
    )

    assert result == "update_incident"
    assert calls == [("INC-1", "FIN-WS-04 is our Jenkins agent, that PowerShell is a build step")]
    # The notice belongs on the incident's own thread, not the analyst's message.
    assert posted[0]["thread_ts"] == "1700000000.000001"


async def test_information_arriving_mid_run_is_deferred_not_dropped(slack_on, posted, monkeypatch):
    deferred: list[str] = []

    async def fake_follow_up(incident_id, note, *, reported_by=""):  # noqa: ARG001
        return "queued"

    async def fake_defer(channel, ts, **kwargs):  # noqa: ARG001
        deferred.append(ts)
        return True

    monkeypatch.setattr(poller.runner, "follow_up_investigation", fake_follow_up)
    monkeypatch.setattr(
        poller.incidents, "get_incident", lambda _id: _async(_incident(status="running"))
    )
    monkeypatch.setattr(poller.slack_watch, "defer", fake_defer)

    result = await poller._act(
        "C_TEST",
        {
            "ts": "1700000009.000000",
            "user": "U",
            "text": "extra context",
            "thread_ts": "",
            "incident_id": "INC-1",
        },
        "update_incident",
        "INC-1",
    )

    assert result == "queued"
    assert deferred == ["1700000009.000000"]
    assert "fold that in" in posted[0]["text"]


async def test_pending_approval_blocks_a_re_assessment(slack_on, posted, monkeypatch):
    """Re-planning under a pending approval would invalidate what the human is deciding."""

    async def fake_follow_up(incident_id, note, *, reported_by=""):  # noqa: ARG001
        return "awaiting_approval"

    monkeypatch.setattr(poller.runner, "follow_up_investigation", fake_follow_up)
    monkeypatch.setattr(
        poller.incidents, "get_incident", lambda _id: _async(_incident(status="awaiting_approval"))
    )
    monkeypatch.setattr(poller.slack_watch, "release", _noop)

    result = await poller._act(
        "C_TEST",
        {
            "ts": "1700000009.000000",
            "user": "U",
            "text": "also seen on FIN-WS-09",
            "thread_ts": "",
            "incident_id": "INC-1",
        },
        "update_incident",
        "INC-1",
    )

    assert result == "blocked_on_approval"
    assert "containment decision" in posted[0]["text"]


async def test_ignored_messages_do_nothing(slack_on, posted, monkeypatch):
    released: list[str] = []

    async def fake_release(channel, ts, *, disposition, incident_id=""):  # noqa: ARG001
        released.append(disposition)

    monkeypatch.setattr(poller.slack_watch, "release", fake_release)

    result = await poller._act(
        "C_TEST",
        {"ts": "1", "user": "U", "text": "thanks!", "thread_ts": "", "incident_id": ""},
        "ignore",
        "",
    )
    assert result == "ignore"
    assert released == ["ignore"]
    assert posted == []


async def test_update_without_an_incident_is_not_guessed_at(slack_on, posted, monkeypatch):
    monkeypatch.setattr(poller.slack_watch, "release", _noop)

    result = await poller._act(
        "C_TEST",
        {"ts": "1", "user": "U", "text": "some new detail", "thread_ts": "", "incident_id": ""},
        "update_incident",
        "",
    )
    assert result == "ignore"
    assert posted == []


# ── Revising a closed incident ───────────────────────────────────────────────
async def test_follow_up_refuses_while_the_run_is_in_flight(monkeypatch):
    from app.services import runner

    monkeypatch.setattr(
        runner.incidents, "get_incident", lambda _id: _async(_incident(status="running"))
    )
    assert await runner.follow_up_investigation("INC-1", "more info") == "queued"


async def test_follow_up_refuses_while_an_approval_is_pending(monkeypatch):
    from app.services import runner

    monkeypatch.setattr(
        runner.incidents, "get_incident", lambda _id: _async(_incident(status="awaiting_approval"))
    )
    assert await runner.follow_up_investigation("INC-1", "more info") == "awaiting_approval"


async def test_follow_up_on_an_unknown_incident(monkeypatch):
    from app.services import runner

    monkeypatch.setattr(runner.incidents, "get_incident", lambda _id: _async(None))
    assert await runner.follow_up_investigation("INC-NOPE", "x") == "unknown"


async def test_revision_reuses_the_thread_and_steers_the_re_run(monkeypatch):
    """The point of a revision: same graph thread, prior findings kept, new
    information handed to the supervisor as the thing to chase."""
    from app.services import runner

    captured: dict[str, Any] = {}

    monkeypatch.setattr(runner.incidents, "get_incident", lambda _id: _async(_incident()))
    monkeypatch.setattr(runner.incidents, "set_status", lambda *a, **k: _async(None))
    monkeypatch.setattr(
        runner,
        "get_graph",
        lambda: SimpleNamespace(
            aget_state=lambda _cfg: _async(
                SimpleNamespace(
                    values={
                        "revision": 1,
                        "alert": {"title": "Encoded PowerShell"},
                        "question": "what is this",
                    },
                    next=(),
                )
            )
        ),
    )

    # Stand in for the real graph run and hold the coroutine so the test drives
    # it, rather than leaving a task running past the assertions.
    async def capture(thread_id, incident_id, payload):
        captured.update({"thread_id": thread_id, "incident_id": incident_id, "payload": payload})

    spawned: list[Any] = []
    monkeypatch.setattr(runner, "_execute", capture)
    monkeypatch.setattr(runner, "_spawn", spawned.append)

    outcome = await runner.follow_up_investigation(
        "INC-1", "host is a build agent", reported_by="U_HUMAN"
    )
    for coro in spawned:
        await coro

    assert outcome == "revising"
    # Same thread as the original incident — findings and checkpoint carry over.
    assert captured["thread_id"] == "INC-1"
    payload = captured["payload"]
    assert payload["revision"] == 2
    assert payload["needs_more_work"] is True
    assert payload["approval"] == {}
    assert "host is a build agent" in payload["critic_feedback"]
    assert payload["alert"]["follow_up_notes"][-1]["note"] == "host is a build agent"


async def test_a_revision_is_labelled_even_when_it_stops_for_approval(monkeypatch):
    """A re-assessment that pauses on the HITL gate must still announce itself,
    or the new approval prompt reads as a duplicate of the first."""
    from app.services import runner

    said: list[str] = []

    async def fake_emit(incident_id, text, *, context=""):  # noqa: ARG001
        said.append(text)

    from app.slack import progress as progress_module

    monkeypatch.setattr(progress_module, "emit", fake_emit)

    await runner._label_revision("INC-1", {"revision": 2})
    assert said and "revision 2" in said[0]

    said.clear()
    await runner._label_revision("INC-1", {"revision": 0})
    assert said == []


# ── Multi-source intake ──────────────────────────────────────────────────────
async def test_an_alert_with_a_channel_but_no_thread_opens_one(slack_on, monkeypatch):
    """A SIEM alert routed to a channel has nowhere to narrate until a thread
    exists, so it would go silent until the final report."""
    from app.services import runner

    monkeypatch.setattr(runner, "get_settings", lambda: slack_on)
    monkeypatch.setattr(
        runner.incidents,
        "create_incident",
        lambda **kw: _async(
            {
                "id": kw["incident_id"],
                "thread_id": kw["thread_id"],
                "title": "SIEM alert",
                "slack_thread_ts": "",
            }
        ),
    )
    attached: list[tuple[str, str, str]] = []

    async def fake_attach(incident_id, channel, ts):
        attached.append((incident_id, channel, ts))

    monkeypatch.setattr(runner.incidents, "attach_slack_thread", fake_attach)
    monkeypatch.setattr(runner, "_spawn", lambda coro: coro.close())

    from app.slack import notifier

    monkeypatch.setattr(notifier, "acknowledge", lambda *a, **k: _async("1700000000.000900"))

    record = await runner.start_investigation(
        alert={"title": "SIEM alert"}, source="siem", slack_channel="C_TEST"
    )

    assert record["slack_thread_ts"] == "1700000000.000900"
    assert attached and attached[0][1:] == ("C_TEST", "1700000000.000900")


async def test_a_failed_acknowledgement_still_starts_the_run(slack_on, monkeypatch):
    """Slack being down must degrade narration, not block the investigation."""
    from app.services import runner

    monkeypatch.setattr(runner, "get_settings", lambda: slack_on)
    monkeypatch.setattr(
        runner.incidents,
        "create_incident",
        lambda **kw: _async(
            {
                "id": kw["incident_id"],
                "thread_id": kw["thread_id"],
                "title": "t",
                "slack_thread_ts": "",
            }
        ),
    )
    started: list[Any] = []
    monkeypatch.setattr(runner, "_spawn", lambda coro: (coro.close(), started.append(1)))

    from app.slack import notifier

    async def boom(*a, **k):
        raise RuntimeError("slack down")

    monkeypatch.setattr(notifier, "acknowledge", boom)

    record = await runner.start_investigation(alert={"title": "t"}, slack_channel="C_TEST")
    assert record["slack_thread_ts"] == ""
    assert started == [1]


# ── Visibility ───────────────────────────────────────────────────────────────
async def test_the_sweep_publishes_what_it_decided_and_why(slack_on, posted):
    await poller._report_decisions(
        "C_TEST",
        [
            {
                "applied": "investigate",
                "incident_id": "INC-9",
                "user": "U1",
                "text": "encoded powershell on FIN-WS-04",
                "reason": "new alert, no existing incident",
            },
            {
                "applied": "ignore",
                "incident_id": "",
                "user": "U2",
                "text": "thanks!",
                "reason": "acknowledgement",
            },
        ],
    )

    assert len(posted) == 1
    body = posted[0]["text"]
    assert "2 message(s) read" in body and "1 acted on" in body


async def test_decision_reporting_can_be_switched_off(slack_on, posted):
    slack_on.slack_poll_report_decisions = False
    await poller._report_decisions(
        "C_TEST",
        [{"applied": "ignore", "incident_id": "", "user": "U", "text": "x", "reason": "y"}],
    )
    assert posted == []


# ── Planning hygiene ─────────────────────────────────────────────────────────
def test_one_specialist_is_not_dispatched_twice_in_a_round():
    """Seen live: three identical `behavioral` agents in one round, three times
    the cost for near-identical findings. Objectives merge; the agent runs once."""
    from app.graph.nodes.supervisor import PlannedTask, _merge_duplicates

    merged = _merge_duplicates(
        [
            PlannedTask(specialist="behavioral", objective="map the beacon interval"),
            PlannedTask(specialist="triage", objective="assess the alert"),
            PlannedTask(specialist="behavioral", objective="check for lateral movement"),
            PlannedTask(specialist="behavioral", objective="map the beacon interval"),
        ]
    )

    assert [t.specialist for t in merged] == ["behavioral", "triage"]
    behavioral = merged[0].objective
    # Both distinct questions survive; the repeated one is not duplicated.
    assert "map the beacon interval" in behavioral
    assert "check for lateral movement" in behavioral
    assert behavioral.count("map the beacon interval") == 1


def test_distinct_specialists_are_left_alone():
    from app.graph.nodes.supervisor import PlannedTask, _merge_duplicates

    tasks = [
        PlannedTask(specialist="triage", objective="a"),
        PlannedTask(specialist="enrichment", objective="b"),
    ]
    assert [t.objective for t in _merge_duplicates(tasks)] == ["a", "b"]


# ── Helpers ──────────────────────────────────────────────────────────────────
def _async(value: Any):
    async def _coro():
        return value

    return _coro()


async def _noop(*args: Any, **kwargs: Any) -> None:
    return None
