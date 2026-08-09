"""Reconstructing duration and overlap from a list of point events.

The stored timeline records instants. The questions worth asking of a finished
investigation — where did the time go, what ran in parallel, which pass reached
the conclusion — are about spans. Everything here pins down that reconstruction,
including the cases where it must refuse to guess.
"""

from __future__ import annotations

from app.services.timeline import build

# A real run: three specialists in parallel, a second round, then a revision.
TIMELINE = [
    {"at": "2026-08-08T21:27:21+00:00", "actor": "intake", "event": "Incident opened"},
    {
        "at": "2026-08-08T21:27:30+00:00",
        "actor": "supervisor",
        "event": "Round 1: dispatched triage, enrichment, behavioral",
    },
    {"at": "2026-08-08T21:27:48+00:00", "actor": "behavioral", "event": "Reported 2 finding(s)"},
    {"at": "2026-08-08T21:27:52+00:00", "actor": "enrichment", "event": "Reported 3 finding(s)"},
    {"at": "2026-08-08T21:27:56+00:00", "actor": "triage", "event": "Reported 3 finding(s)"},
    {"at": "2026-08-08T21:28:07+00:00", "actor": "critic", "event": "Review: inconclusive"},
    {
        "at": "2026-08-08T21:28:22+00:00",
        "actor": "supervisor",
        "event": "Round 2: dispatched enrichment, behavioral",
    },
    {"at": "2026-08-08T21:28:47+00:00", "actor": "enrichment", "event": "Reported 2 finding(s)"},
    {"at": "2026-08-08T21:28:55+00:00", "actor": "behavioral", "event": "Reported 3 finding(s)"},
    {"at": "2026-08-08T21:29:01+00:00", "actor": "critic", "event": "Review: closed"},
    {"at": "2026-08-08T21:29:12+00:00", "actor": "containment_planner", "event": "Proposed 2"},
    {"at": "2026-08-08T21:29:30+00:00", "actor": "human:scenario", "event": "Approved 2 of 2"},
    {"at": "2026-08-08T21:29:30+00:00", "actor": "executor", "event": "Executed 2"},
    {"at": "2026-08-08T21:29:37+00:00", "actor": "intake", "event": "Incident reopened"},
    {
        "at": "2026-08-08T21:29:52+00:00",
        "actor": "supervisor",
        "event": "Round 1: dispatched enrichment",
    },
    {"at": "2026-08-08T21:30:28+00:00", "actor": "enrichment", "event": "Reported 5 finding(s)"},
]


def _lane(chart, actor):
    return next(lane for lane in chart["lanes"] if lane["actor"] == actor)


def test_the_span_is_dispatch_to_report():
    chart = build(TIMELINE)
    triage = _lane(chart, "triage")["spans"]
    assert len(triage) == 1
    # 21:27:30 dispatched -> 21:27:56 reported = 26s, offset 9s from the first event.
    assert triage[0]["start"] == 9.0
    assert triage[0]["end"] - triage[0]["start"] == 26.0
    assert triage[0]["round"] == "1"


def test_parallel_specialists_overlap():
    """The whole point of the picture: three lanes covering the same seconds."""
    chart = build(TIMELINE)
    first = {
        name: _lane(chart, name)["spans"][0] for name in ("triage", "enrichment", "behavioral")
    }
    assert all(s["start"] == 9.0 for s in first.values())
    # They start together and finish apart — that is what a list cannot show.
    assert len({s["end"] for s in first.values()}) == 3


def test_a_specialist_dispatched_twice_gets_two_spans():
    chart = build(TIMELINE)
    # enrichment ran in round 1, round 2, and again in the revision.
    assert [s["round"] for s in _lane(chart, "enrichment")["spans"]] == ["1", "2", "1"]


def test_a_second_intake_starts_a_new_run():
    chart = build(TIMELINE)
    assert [r["label"] for r in chart["runs"]] == ["initial", "revision 1"]
    # The initial run ends where the revision begins — bands must not overlap.
    assert chart["runs"][0]["end"] == chart["runs"][1]["start"]


def test_actors_without_a_dispatch_stay_as_markers():
    chart = build(TIMELINE)
    critic = _lane(chart, "critic")
    assert critic["spans"] == []
    assert len(critic["marks"]) == 2


def test_lanes_read_in_pipeline_order():
    chart = build(TIMELINE)
    order = [lane["actor"] for lane in chart["lanes"]]
    assert order.index("supervisor") < order.index("triage")
    assert order.index("triage") < order.index("critic")
    assert order.index("critic") < order.index("executor")
    # The human gate sits between planning containment and running it.
    # Lane labels are humanised, so `containment_planner` reads as two words.
    assert order.index("containment planner") < order.index("scenario") < order.index("executor")


def test_a_failure_is_marked_as_one():
    chart = build(
        [
            {"at": "2026-08-08T21:00:00+00:00", "actor": "intake", "event": "opened"},
            {
                "at": "2026-08-08T21:00:05+00:00",
                "actor": "supervisor",
                "event": "Round 1: dispatched behavioral",
            },
            {
                "at": "2026-08-08T21:00:20+00:00",
                "actor": "behavioral",
                "event": "Specialist failed: TimeoutError",
            },
        ]
    )
    assert _lane(chart, "behavioral")["spans"][0]["failed"] is True


def test_a_specialist_that_never_reported_is_flagged_open():
    """It was dispatched and nothing came back. The bar is an inference, not a
    measurement, and the template renders it faded to say so."""
    chart = build(
        [
            {"at": "2026-08-08T21:00:00+00:00", "actor": "intake", "event": "opened"},
            {
                "at": "2026-08-08T21:00:05+00:00",
                "actor": "supervisor",
                "event": "Round 1: dispatched triage",
            },
            {"at": "2026-08-08T21:00:40+00:00", "actor": "critic", "event": "Review"},
        ]
    )
    span = _lane(chart, "triage")["spans"][0]
    assert span["open"] is True


# ── Refusing to guess ────────────────────────────────────────────────────────
def test_an_empty_timeline_is_empty_not_broken():
    chart = build([])
    assert chart["empty"] is True
    assert chart["lanes"] == []


def test_unparseable_timestamps_are_skipped_not_fatal():
    chart = build(
        [
            {"at": "not a date", "actor": "intake", "event": "x"},
            {"at": None, "actor": "supervisor", "event": "y"},
            {"at": "2026-08-08T21:00:00+00:00", "actor": "critic", "event": "Review"},
        ]
    )
    assert chart["empty"] is False
    assert [lane["actor"] for lane in chart["lanes"]] == ["critic"]


def test_a_single_instant_does_not_divide_by_zero():
    chart = build([{"at": "2026-08-08T21:00:00+00:00", "actor": "intake", "event": "opened"}])
    assert chart["total"] == 1.0
    assert chart["ticks"]


def test_ticks_stay_readable_across_scales():
    """Six-ish marks whether the run took forty seconds or forty minutes."""
    for seconds, cap in ((40, 9), (600, 9), (5400, 9)):
        chart = build(
            [
                {"at": "2026-08-08T21:00:00+00:00", "actor": "intake", "event": "a"},
                {
                    "at": f"2026-08-08T{21 + seconds // 3600:02d}:"
                    f"{(seconds % 3600) // 60:02d}:{seconds % 60:02d}+00:00",
                    "actor": "reporter",
                    "event": "b",
                },
            ]
        )
        assert 2 <= len(chart["ticks"]) <= cap
