"""Phase durations, and the honesty of the labels on them.

The number a SOC is asked for is MTTR. On one incident that is not a mean, and
calling it one is how a metric quietly stops meaning anything — so `measure`
reports TT*, `fleet` reports MTT*, and the tests hold that line.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.services import timings

T0 = datetime(2026, 8, 9, 12, 0, 0, tzinfo=UTC)


def at(seconds: int) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat()


def entry(seconds: int, actor: str, event: str = "") -> dict:
    return {"at": at(seconds), "actor": actor, "event": event}


def incident(*entries: dict, status: str = "completed", **extra) -> dict:
    return {
        "created_at": T0.isoformat(),
        "updated_at": entries[-1]["at"] if entries else T0.isoformat(),
        "status": status,
        "timeline": list(entries),
        **extra,
    }


# ── Formatting ───────────────────────────────────────────────────────────────
def test_durations_read_as_durations() -> None:
    assert timings.humanise(0) == "0s"
    assert timings.humanise(42) == "42s"
    assert timings.humanise(72) == "1m 12s"
    assert timings.humanise(3600) == "1h 00m"
    assert timings.humanise(5430) == "1h 30m"
    assert timings.humanise(None) == "—"


def test_a_negative_duration_is_clamped_not_shown() -> None:
    """Clock skew between a SIEM and us must not print `-3s to contain`."""
    assert timings.humanise(-5) == "0s"


# ── Phases ───────────────────────────────────────────────────────────────────
def test_each_phase_is_measured_from_the_right_mark() -> None:
    record = incident(
        entry(0, "intake"),
        entry(30, "enrichment", "Reported 3 finding(s)"),
        entry(45, "critic", "Review: true_positive"),
        entry(60, "containment_planner", "Proposed 2 containment action(s)"),
        entry(90, "human:alice", "Approved 2 of 2 action(s)"),
        entry(95, "executor", "Executed 2 action(s)"),
        entry(120, "reporter", "Incident report generated"),
    )
    by_abbr = {p["abbr"]: p["seconds"] for p in timings.measure(record)["phases"]}
    assert by_abbr["TTA"] == 30
    assert by_abbr["TTT"] == 45
    assert by_abbr["TTP"] == 60
    assert by_abbr["TTC"] == 95
    assert by_abbr["TTR"] == 120


def test_a_phase_that_never_happened_is_absent_not_zero() -> None:
    """Zero would read as instant. Absent reads as what it is."""
    record = incident(entry(0, "intake"), entry(20, "critic"), status="running")
    measured = timings.measure(record)
    assert "TTC" not in {p["abbr"] for p in measured["phases"]}
    assert "TTC" in measured["missing"]


def test_detection_lag_needs_the_alert_to_carry_a_timestamp() -> None:
    plain = incident(entry(0, "intake"), entry(10, "reporter"))
    assert "TTD" in timings.measure(plain)["missing"]

    stamped = incident(
        entry(0, "intake"),
        entry(10, "reporter"),
        alert={"detected_at": (T0 - timedelta(minutes=5)).isoformat()},
    )
    by_abbr = {p["abbr"]: p["seconds"] for p in timings.measure(stamped)["phases"]}
    assert by_abbr["TTD"] == 300


def test_the_first_of_each_mark_wins_but_the_last_report_does() -> None:
    """Revisions re-run the spine. First evidence is the first ever; the report
    is the one that superseded the others."""
    record = incident(
        entry(0, "intake"),
        entry(20, "triage"),
        entry(40, "reporter"),
        entry(50, "intake"),
        entry(70, "triage"),
        entry(100, "reporter"),
    )
    by_abbr = {p["abbr"]: p["seconds"] for p in timings.measure(record)["phases"]}
    assert by_abbr["TTA"] == 20
    assert by_abbr["TTR"] == 100


# ── The split that matters ───────────────────────────────────────────────────
def test_time_waiting_on_a_human_is_measured_separately() -> None:
    record = incident(
        entry(0, "intake"),
        entry(60, "containment_planner", "Proposed 1 containment action(s)"),
        entry(660, "human:alice", "Approved 1 of 1 action(s)"),
        entry(665, "executor", "Executed 1 action(s)"),
        entry(700, "reporter"),
    )
    measured = timings.measure(record)
    assert measured["waiting_seconds"] == 600
    assert measured["human_share"] == 86  # 600 of 700
    assert measured["machine"] == "1m 40s"
    assert measured["gates"] == 1


def test_every_gate_counts_not_just_the_first() -> None:
    record = incident(
        entry(0, "intake"),
        entry(10, "containment_planner"),
        entry(70, "human:alice", "Approved 1 of 1 action(s)"),
        entry(80, "containment_planner"),
        entry(200, "human:bob", "Approved 2 of 2 action(s)"),
        entry(210, "reporter"),
    )
    measured = timings.measure(record)
    assert measured["gates"] == 2
    assert measured["waiting_seconds"] == 60 + 120


def test_an_incident_still_at_a_gate_is_still_accruing_wait() -> None:
    """An unattended queue is not free, and reporting it as zero says it is."""
    now = datetime.now(UTC)
    record = {
        "created_at": (now - timedelta(minutes=10)).isoformat(),
        "updated_at": (now - timedelta(minutes=8)).isoformat(),
        "status": "awaiting_approval",
        "timeline": [
            {"at": (now - timedelta(minutes=10)).isoformat(), "actor": "intake", "event": ""},
            {
                "at": (now - timedelta(minutes=8)).isoformat(),
                "actor": "containment_planner",
                "event": "Proposed 1",
            },
        ],
    }
    measured = timings.measure(record)
    assert measured["waiting_seconds"] is not None
    assert measured["waiting_seconds"] > 420  # roughly the 8 minutes since the gate opened
    assert measured["gates"] == 1


def test_a_human_comment_that_is_not_a_decision_does_not_close_the_gate() -> None:
    record = incident(
        entry(0, "intake"),
        entry(10, "containment_planner"),
        entry(30, "human:alice", "Revision 1 triggered by new information: more telemetry"),
        entry(130, "human:bob", "Approved 1 of 1 action(s)"),
        entry(140, "reporter"),
    )
    assert timings.measure(record)["waiting_seconds"] == 120


def test_an_incident_with_no_gate_reports_no_human_wait() -> None:
    record = incident(entry(0, "intake"), entry(50, "reporter"))
    measured = timings.measure(record)
    assert measured["waiting_seconds"] is None
    assert measured["human_share"] == 0
    assert measured["machine"] == measured["total"]


def test_an_open_incident_is_measured_to_now_and_says_so() -> None:
    record = incident(entry(0, "intake"), entry(30, "critic"), status="running")
    measured = timings.measure(record)
    assert measured["open"] is True
    assert "still running" in next(p["note"] for p in measured["phases"] if p["abbr"] == "TTR")


# ── The M in MTTR ────────────────────────────────────────────────────────────
def test_the_mean_is_labelled_as_a_mean() -> None:
    one = incident(entry(0, "intake"), entry(100, "reporter"))
    two = incident(entry(0, "intake"), entry(200, "reporter"))
    result = timings.fleet([one, two])
    ttr = next(p for p in result["phases"] if p["abbr"] == "MTTR")
    assert ttr["seconds"] == 150
    assert ttr["samples"] == 2
    assert result["count"] == 2


def test_open_incidents_are_left_out_of_the_mean() -> None:
    """Averaging in a run nobody closed drags MTTR toward how long ago it was
    forgotten about."""
    done = incident(entry(0, "intake"), entry(100, "reporter"))
    running = incident(entry(0, "intake"), entry(9999, "critic"), status="running")
    result = timings.fleet([done, running])
    assert result["count"] == 1
    assert next(p for p in result["phases"] if p["abbr"] == "MTTR")["seconds"] == 100


def test_a_fleet_with_nothing_closed_reports_nothing_rather_than_zero() -> None:
    result = timings.fleet([incident(entry(0, "intake"), status="running")])
    assert result == {"count": 0, "phases": []}


# ── Questions ────────────────────────────────────────────────────────────────
def test_asked_questions_are_recovered_from_the_timeline() -> None:
    """`open_questions` holds only what is outstanding, so the answered ones
    exist nowhere else."""
    record = incident(
        entry(0, "intake"),
        entry(10, "critic", "Asked: Was a migration scheduled?"),
        entry(20, "critic", "Asked: Is 10.4.2.19 a build agent?"),
        open_questions=["Is 10.4.2.19 a build agent?"],
    )
    result = timings.questions(record)
    assert result["resolved"] == 1
    assert result["open"] == 1
    by_text = {q["question"]: q["resolved"] for q in result["asked"]}
    assert by_text["Was a migration scheduled?"] is True
    assert by_text["Is 10.4.2.19 a build agent?"] is False


def test_the_same_question_asked_twice_is_listed_once() -> None:
    record = incident(
        entry(10, "critic", "Asked: Was a migration scheduled?"),
        entry(20, "critic", "Asked: Was a migration scheduled?"),
    )
    assert len(timings.questions(record)["asked"]) == 1


def test_a_question_raised_but_not_yet_asked_still_shows() -> None:
    """Raised on the current pass, before the ask went out."""
    record = incident(entry(0, "intake"), open_questions=["Who owns FIN-WS-04?"])
    result = timings.questions(record)
    assert [q["question"] for q in result["asked"]] == ["Who owns FIN-WS-04?"]
    assert result["open"] == 1


def test_responses_are_listed_not_matched_to_a_question() -> None:
    """Nobody quotes the question back, so pairing would be a guess."""
    record = incident(
        entry(10, "critic", "Asked: Was a migration scheduled?"),
        pending_notes=[{"at": at(60), "by": "alice", "note": "No migration was scheduled."}],
    )
    result = timings.questions(record)
    assert len(result["answers"]) == 1
    assert result["answers"][0]["by"] == "alice"
    assert "resolved" not in result["answers"][0]


def test_an_incident_that_asked_nothing_reports_nothing() -> None:
    result = timings.questions(incident(entry(0, "intake")))
    assert result["asked"] == [] and result["resolved"] == 0 and result["open"] == 0
