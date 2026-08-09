"""What the platform does during the hours when nothing is running.

A fifteen-minute incident exercises none of this. A five-hour one is mostly
this: parked at a gate, accumulating notes, going quiet. The failures being
pinned down here are the ones that only appear on that timescale — a queue that
can never drain, a plan approved on a picture three hours out of date, and a
withdrawal that quietly bills itself to a human who was never there.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.services import incidents, runner, upkeep


def _settings(**overrides: Any) -> SimpleNamespace:
    base = {
        "stale_gate_seconds": 1800,
        "ir_digest_seconds": 600,
        "slack_enabled": False,
        "upkeep_enabled": True,
        "upkeep_interval_seconds": 60,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


# ── Withdrawing a plan that went stale ───────────────────────────────────────
@pytest.fixture
def withdrawal(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Wire up what `withdraw_plan` touches, recording the resume payload."""
    state: dict[str, Any] = {
        "record": {"id": "INC-1", "thread_id": "t-1", "status": "awaiting_approval"},
        "status_writes": [],
        "resumed": [],
        "quiet": [],
    }

    async def _get(incident_id: str) -> dict[str, Any] | None:  # noqa: ARG001
        return state["record"]

    async def _set_status(incident_id: str, status: str) -> None:
        state["status_writes"].append((incident_id, status))

    def _spawn(coro: Any) -> None:
        coro.close()
        return None

    def _execute(thread_id: str, incident_id: str, payload: Any, *, quiet: bool = False) -> Any:
        state["resumed"].append(payload)
        state["quiet"].append(quiet)

        async def _noop() -> None:
            return None

        return _noop()

    monkeypatch.setattr(runner.incidents, "get_incident", _get)
    monkeypatch.setattr(runner.incidents, "set_status", _set_status)
    monkeypatch.setattr(runner, "_spawn", _spawn)
    monkeypatch.setattr(runner, "_execute", _execute)
    return state


async def test_a_stale_plan_is_withdrawn_without_approving_anything(
    withdrawal: dict[str, Any],
) -> None:
    """The one thing a withdrawal must never do is execute."""
    assert await runner.withdraw_plan("INC-1", reason="stale") == "withdrawn"

    resume = withdrawal["resumed"][0].resume
    assert resume["approved_all"] is False
    assert resume["approved_actions"] == []
    assert resume["withdrawn"] is True


async def test_a_withdrawal_runs_quietly_because_a_revision_supersedes_it(
    withdrawal: dict[str, Any],
) -> None:
    await runner.withdraw_plan("INC-1", reason="stale")
    assert withdrawal["quiet"] == [True]


async def test_an_incident_decided_since_the_sweep_read_it_is_left_alone(
    withdrawal: dict[str, Any],
) -> None:
    """The sweep reads rows, then acts on them; an approver can land in between."""
    withdrawal["record"] = {"id": "INC-1", "thread_id": "t-1", "status": "running"}
    assert await runner.withdraw_plan("INC-1", reason="stale") == "not_gated"
    assert withdrawal["resumed"] == []


async def test_an_unknown_incident_is_not_invented(withdrawal: dict[str, Any]) -> None:
    withdrawal["record"] = None
    assert await runner.withdraw_plan("INC-1", reason="stale") == "unknown"


async def test_a_withdrawal_is_recorded_as_the_machine_not_as_a_human(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`human:` on the timeline drives the waiting-on-people metric.

    Attributing the system's own housekeeping to a person would inflate the
    single number this platform exists to report honestly, and would put a
    rejection in the record that nobody made.
    """
    import app.graph.nodes.containment as containment_mod

    monkeypatch.setattr(
        containment_mod,
        "interrupt",
        lambda _payload: {
            "approved_all": False,
            "approved_actions": [],
            "approver": "system",
            "withdrawn": True,
            "note": "superseded",
        },
    )

    result = await containment_mod.approval_node(
        {
            "incident_id": "INC-1",
            "containment_actions": [{"action": "isolate_host", "requires_approval": True}],
        }  # type: ignore[arg-type]
    )

    entry = result["timeline"][0]
    assert entry["actor"] == "system"
    assert entry["event"].startswith("Plan withdrawn")
    assert result["approval"]["withdrawn"] is True
    assert result["approval"]["approved_actions"] == []


async def test_a_real_rejection_is_still_attributed_to_the_person_who_made_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The withdrawal path must not swallow the ordinary one."""
    import app.graph.nodes.containment as containment_mod

    monkeypatch.setattr(
        containment_mod,
        "interrupt",
        lambda _payload: {"approved_all": False, "approved_actions": [], "approver": "U123"},
    )

    result = await containment_mod.approval_node(
        {
            "incident_id": "INC-1",
            "containment_actions": [{"action": "isolate_host", "requires_approval": True}],
        }  # type: ignore[arg-type]
    )
    assert result["timeline"][0]["actor"] == "human:U123"
    assert result["approval"]["withdrawn"] is False


def test_a_withdrawn_gate_still_counts_as_time_spent_waiting_on_a_person() -> None:
    """Nobody came, so the wait was real — losing it would flatter the metric."""
    from app.services import timings

    record = {
        "status": "completed",
        "created_at": "2026-08-09T10:00:00+00:00",
        "updated_at": "2026-08-09T12:05:00+00:00",
        "timeline": [
            {"at": "2026-08-09T10:00:00+00:00", "actor": "intake", "event": "Incident opened"},
            {
                "at": "2026-08-09T10:05:00+00:00",
                "actor": "containment_planner",
                "event": "Proposed 2 containment action(s)",
            },
            {
                "at": "2026-08-09T12:00:00+00:00",
                "actor": "system",
                "event": "Plan withdrawn before any decision — superseded",
            },
            {"at": "2026-08-09T12:05:00+00:00", "actor": "reporter", "event": "report"},
        ],
    }
    measured = timings.measure(record)
    assert measured["waiting_seconds"] == pytest.approx(115 * 60)
    assert measured["gates"] == 1
    assert measured["human_share"] == 92


# ── The queue that could never drain ─────────────────────────────────────────
async def test_applying_nothing_reports_that_it_started_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`_execute` decides whether to stay quiet on this answer."""

    async def _drain(incident_id: str) -> list[dict[str, Any]]:  # noqa: ARG001
        return []

    monkeypatch.setattr(runner.incidents, "drain_notes", _drain)
    assert await runner._apply_pending("INC-1") is False


async def test_a_drained_queue_reports_the_revision_it_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _drain(incident_id: str) -> list[dict[str, Any]]:  # noqa: ARG001
        return [{"by": "U1", "note": "that host is a build agent"}]

    seen: list[str] = []

    async def _follow(incident_id: str, note: str, *, reported_by: str = "") -> str:  # noqa: ARG001
        seen.append(note)
        return "revising"

    monkeypatch.setattr(runner.incidents, "drain_notes", _drain)
    monkeypatch.setattr(runner, "follow_up_investigation", _follow)

    assert await runner._apply_pending("INC-1") is True
    assert "build agent" in seen[0]


# ── The caretaker sweep ──────────────────────────────────────────────────────
@pytest.fixture
def caretaker(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {
        "settings": _settings(),
        "stale": [],
        "withdrawn": [],
        "outcome": "withdrawn",
        "due": [],
        "posted": [],
        "digested": [],
        "digest_result": True,
    }

    async def _stale(after_seconds: int, limit: int = 25) -> list[dict[str, Any]]:  # noqa: ARG001
        return state["stale"]

    async def _withdraw(incident_id: str, *, reason: str) -> str:
        state["withdrawn"].append((incident_id, reason))
        return state["outcome"]

    async def _due(interval_seconds: int, limit: int = 25) -> list[dict[str, Any]]:  # noqa: ARG001
        return state["due"]

    async def _get(incident_id: str) -> dict[str, Any] | None:
        return next((r for r in state["due"] if r["id"] == incident_id), None)

    async def _mark(incident_id: str) -> None:
        state["digested"].append(incident_id)

    async def _post(record: dict[str, Any]) -> bool:
        state["posted"].append(record["id"])
        return bool(state["digest_result"])

    monkeypatch.setattr(upkeep, "get_settings", lambda: state["settings"])
    monkeypatch.setattr(upkeep.incidents, "stale_gates", _stale)
    monkeypatch.setattr(upkeep.incidents, "due_for_digest", _due)
    monkeypatch.setattr(upkeep.incidents, "get_incident", _get)
    monkeypatch.setattr(upkeep.incidents, "mark_digested", _mark)
    monkeypatch.setattr(runner, "withdraw_plan", _withdraw)

    from app.slack import digest

    monkeypatch.setattr(digest, "post", _post)
    return state


async def test_a_stale_gate_with_notes_is_replanned(caretaker: dict[str, Any]) -> None:
    caretaker["stale"] = [{"id": "INC-1", "pending_notes": [{"note": "a"}, {"note": "b"}]}]
    assert await upkeep.replan_stale_gates() == 1
    incident_id, reason = caretaker["withdrawn"][0]
    assert incident_id == "INC-1"
    assert "2 update(s)" in reason


async def test_replanning_can_be_switched_off_entirely(caretaker: dict[str, Any]) -> None:
    """An operator who wants plans to wait indefinitely must be able to say so."""
    caretaker["settings"] = _settings(stale_gate_seconds=0)
    caretaker["stale"] = [{"id": "INC-1", "pending_notes": [{"note": "a"}]}]
    assert await upkeep.replan_stale_gates() == 0
    assert caretaker["withdrawn"] == []


async def test_a_backlog_of_stale_gates_does_not_stampede(caretaker: dict[str, Any]) -> None:
    """Ten gates going stale at once must not launch ten concurrent re-plans."""
    caretaker["stale"] = [{"id": f"INC-{i}", "pending_notes": [{"note": "a"}]} for i in range(10)]
    assert await upkeep.replan_stale_gates() == upkeep._MAX_WITHDRAWALS
    assert len(caretaker["withdrawn"]) == upkeep._MAX_WITHDRAWALS


async def test_a_gate_decided_mid_sweep_is_not_counted(caretaker: dict[str, Any]) -> None:
    caretaker["stale"] = [{"id": "INC-1", "pending_notes": [{"note": "a"}]}]
    caretaker["outcome"] = "not_gated"
    assert await upkeep.replan_stale_gates() == 0


async def test_digests_go_out_and_the_clock_is_stamped(caretaker: dict[str, Any]) -> None:
    caretaker["settings"] = _settings(slack_enabled=True)
    caretaker["due"] = [{"id": "INC-1"}, {"id": "INC-2"}]
    assert await upkeep.post_digests() == 2
    assert caretaker["digested"] == ["INC-1", "INC-2"]


async def test_a_digest_with_nothing_to_say_does_not_reset_the_cadence(
    caretaker: dict[str, Any],
) -> None:
    """Stamping a skipped digest would make the next real change wait a full
    interval before anyone heard about it."""
    caretaker["settings"] = _settings(slack_enabled=True)
    caretaker["due"] = [{"id": "INC-1"}]
    caretaker["digest_result"] = False

    assert await upkeep.post_digests() == 0
    assert caretaker["digested"] == []


async def test_digests_are_skipped_when_slack_is_off(caretaker: dict[str, Any]) -> None:
    caretaker["due"] = [{"id": "INC-1"}]
    assert await upkeep.post_digests() == 0
    assert caretaker["posted"] == []


async def test_one_failing_duty_does_not_take_out_the_other(
    caretaker: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def _boom() -> int:
        raise RuntimeError("postgres went away")

    monkeypatch.setattr(upkeep, "replan_stale_gates", _boom)
    caretaker["settings"] = _settings(slack_enabled=True)
    caretaker["due"] = [{"id": "INC-1"}]

    result = await upkeep.sweep()
    assert result == {"withdrawn": 0, "digests": 1}


async def test_the_caretaker_can_be_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(upkeep, "get_settings", lambda: _settings(upkeep_enabled=False))
    upkeep.start()
    assert upkeep._task is None


# ── Which rows count as stale ────────────────────────────────────────────────
def _ago(minutes: int) -> str:
    return (datetime.now(UTC) - timedelta(minutes=minutes)).isoformat()


class _Row:
    def __init__(self, incident_id: str, notes: list[dict[str, Any]]) -> None:
        self.id = incident_id
        self.pending_notes = notes

    def as_dict(self, *, include_report: bool = True) -> dict[str, Any]:  # noqa: ARG002
        return {"id": self.id, "pending_notes": self.pending_notes}


@pytest.fixture
def rows(monkeypatch: pytest.MonkeyPatch) -> list[_Row]:
    found: list[_Row] = []

    class _Result:
        def scalars(self) -> Any:
            return SimpleNamespace(all=lambda: found)

    class _Session:
        async def execute(self, *_a: Any, **_k: Any) -> _Result:
            return _Result()

    class _Scope:
        async def __aenter__(self) -> _Session:
            return _Session()

        async def __aexit__(self, *_a: Any) -> None:
            return None

    monkeypatch.setattr("app.services.incidents.session_scope", lambda: _Scope())
    return found


async def test_a_gate_with_no_new_information_is_not_stale(rows: list[_Row]) -> None:
    """Age alone does not make a plan wrong.

    A plan nobody has objected to is still the best plan anyone has, however
    long it has waited. Withdrawing on the clock alone would make an approval
    that arrives late impossible to ever act on.
    """
    rows.extend(
        [
            _Row("INC-quiet", []),
            _Row("INC-busy", [{"at": _ago(45), "note": "new telemetry"}]),
        ]
    )
    stale = await incidents.stale_gates(1800)
    assert [r["id"] for r in stale] == ["INC-busy"]


async def test_information_that_only_just_arrived_does_not_yank_the_plan(
    rows: list[_Row],
) -> None:
    """A note a minute old rarely overturns a plan, and re-planning on every one
    would make the gate impossible to ever approve."""
    rows.append(_Row("INC-fresh", [{"at": _ago(2), "note": "same host again"}]))
    assert await incidents.stale_gates(1800) == []


async def test_the_clock_runs_from_the_oldest_note_not_the_newest(rows: list[_Row]) -> None:
    """`updated_at` moves on every queued note, so measuring from it would reset
    the timer on exactly the incidents carrying the most new information — the
    busier the incident, the longer it would stay frozen."""
    rows.append(
        _Row(
            "INC-busy",
            [
                {"at": _ago(90), "note": "held for an hour and a half"},
                {"at": _ago(1), "note": "and one just now"},
            ],
        )
    )
    assert [r["id"] for r in await incidents.stale_gates(1800)] == ["INC-busy"]


async def test_a_note_with_no_usable_timestamp_is_not_treated_as_ancient(
    rows: list[_Row],
) -> None:
    """Defaulting an unparseable stamp to the epoch would withdraw a plan the
    moment any malformed note landed behind it."""
    rows.append(_Row("INC-odd", [{"at": "not a date", "note": "x"}, {"note": "y"}]))
    assert await incidents.stale_gates(1800) == []


async def test_staleness_is_off_when_the_window_is_zero(rows: list[_Row]) -> None:
    rows.append(_Row("INC-busy", [{"at": _ago(999), "note": "new telemetry"}]))
    assert await incidents.stale_gates(0) == []


# ── War rooms in the sweep ───────────────────────────────────────────────────
async def test_live_war_rooms_are_swept_alongside_the_configured_channels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A room nobody reads is worse than no room: people talk into it and
    reasonably assume it reaches the bot."""
    from app.slack import poller

    monkeypatch.setattr(
        poller,
        "get_settings",
        lambda: SimpleNamespace(polled_channels=["C_SHARED"], slack_poll_thread_window_hours=24),
    )

    async def _resolve(name: str) -> str:
        return name

    async def _active(window_hours: int, limit: int = 60) -> list[str]:  # noqa: ARG001
        return ["C_ROOM1", "C_SHARED", "C_ROOM2"]

    async def _owner(channel: str) -> dict[str, Any] | None:
        return {"id": f"INC-{channel}"}

    monkeypatch.setattr(poller, "resolve_channel", _resolve)
    monkeypatch.setattr(poller.incidents, "active_channels", _active)
    monkeypatch.setattr(poller.incidents, "get_by_slack_channel", _owner)

    watched = await poller.watched_channels()
    assert watched == [
        ("C_SHARED", ""),  # configured, and not claimed by an incident
        ("C_ROOM1", "INC-C_ROOM1"),
        ("C_ROOM2", "INC-C_ROOM2"),
    ]


async def test_losing_the_room_list_still_sweeps_the_configured_channels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.slack import poller

    monkeypatch.setattr(
        poller,
        "get_settings",
        lambda: SimpleNamespace(polled_channels=["C_SHARED"], slack_poll_thread_window_hours=24),
    )

    async def _resolve(name: str) -> str:
        return name

    async def _boom(window_hours: int, limit: int = 60) -> list[str]:  # noqa: ARG001
        raise RuntimeError("db down")

    monkeypatch.setattr(poller, "resolve_channel", _resolve)
    monkeypatch.setattr(poller.incidents, "active_channels", _boom)

    assert await poller.watched_channels() == [("C_SHARED", "")]


async def test_a_new_alert_posted_in_a_war_room_joins_that_incident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opening a second incident there would take the room over — the new
    incident would claim the channel and everything later said in it would be
    attributed to the wrong investigation."""
    from app.slack import poller

    folded: list[tuple[str, str]] = []

    async def _follow(incident_id: str, text: str, *, reported_by: str = "") -> str:  # noqa: ARG001
        folded.append((incident_id, text))
        return "revising"

    async def _get(incident_id: str) -> dict[str, Any]:
        return {"id": incident_id, "slack_thread_ts": ""}

    async def _release(*_a: Any, **_k: Any) -> None:
        return None

    async def _post(*_a: Any, **_k: Any) -> str:
        return "1.0"

    started: list[str] = []

    async def _start(**kwargs: Any) -> dict[str, Any]:
        started.append(kwargs.get("question", ""))
        return {"id": "INC-NEW", "title": "x"}

    monkeypatch.setattr(poller.runner, "follow_up_investigation", _follow)
    monkeypatch.setattr(poller.runner, "start_investigation", _start)
    monkeypatch.setattr(poller.incidents, "get_incident", _get)
    monkeypatch.setattr(poller.slack_watch, "release", _release)
    monkeypatch.setattr("app.slack.notifier.post", _post)

    candidate = {"ts": "1.0", "user": "U1", "text": "same thing on FIN-WS-09", "thread_ts": ""}
    applied = await poller._act("C_ROOM", candidate, "investigate", "", owner="INC-ROOM")

    assert applied == "update_incident"
    assert started == [], "a war room must never spawn a second incident"
    assert folded == [("INC-ROOM", "same thing on FIN-WS-09")]


def test_the_stale_window_default_is_measured_in_tens_of_minutes() -> None:
    """Short enough that a five-hour incident is not frozen for most of it,
    long enough that a normal approval is never yanked out from under someone."""
    from app.config import Settings

    assert 600 <= Settings.model_fields["stale_gate_seconds"].default <= 3600


def test_recent_window_helper_is_timezone_safe() -> None:
    from app.slack import digest

    naive = datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=5)
    assert digest._parse(naive) is not None
    assert digest._parse(naive).tzinfo is UTC  # type: ignore[union-attr]
