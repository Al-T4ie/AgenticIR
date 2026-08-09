"""How long each phase of an incident took, and where the time actually went.

The number every SOC reports is MTTR, and on a single incident it is not a
mean — it is one measurement. This module computes the per-incident durations
honestly (TTA, TTT, TTC, TTR) and leaves the averaging to a caller that has
more than one incident in hand. Labelling a single incident's 12 minutes as
"MTTR" is how a metric stops meaning anything.

The measurement worth having is not the total. It is the split between time the
machine spent and time the incident spent waiting on a person: an agentic
platform can only compress the first, and if the second dominates then the
investigation speed was never the bottleneck. `waiting_on_humans` is the number
that tells you whether this thing is helping.

Everything is derived from the timeline, so it works on any incident already in
the database with no extra recording.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

# Timeline actors that mean "a person did something", as opposed to the graph.
_HUMAN = ("human:", "channel")

# The marks we look for, in the order they occur.
_FIRST_EVIDENCE = ("triage", "enrichment", "behavioral")


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _is_human(actor: str) -> bool:
    return actor.startswith(_HUMAN[0]) or actor == _HUMAN[1]


def humanise(seconds: float | None) -> str:
    """`4m 12s`. Short enough to sit in a table cell."""
    if seconds is None:
        return "—"
    seconds = max(0.0, float(seconds))
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60):02d}s"
    hours, rest = divmod(int(seconds), 3600)
    return f"{hours}h {rest // 60:02d}m"


def _actors_between(
    timeline: list[dict[str, Any]], start: datetime | None, end: datetime | None
) -> list[str]:
    """Distinct non-human actors that reported inside a window, in order.

    Humans are excluded on purpose: the point of the list is what the machine
    was doing while the clock ran, and the human contribution is already broken
    out as the waiting figure.
    """
    if start is None or end is None:
        return []
    seen: list[str] = []
    for entry in timeline:
        at = _parse(entry.get("at"))
        if at is None or at < start or at > end:
            continue
        actor = str(entry.get("actor", ""))
        if not actor or _is_human(actor) or actor in seen:
            continue
        seen.append(actor)
    return seen


def measure(record: dict[str, Any]) -> dict[str, Any]:
    """Phase durations for one incident, in seconds, plus formatted strings.

    Spans the whole incident including revisions: a responder who reopened an
    incident twice waited for all of it, and reporting only the first pass would
    flatter the number.
    """
    timeline = record.get("timeline") or []
    marks: dict[str, datetime] = {}
    human_waits: list[tuple[datetime, datetime]] = []

    opened = _parse(record.get("created_at"))
    first_gate: datetime | None = None

    for entry in timeline:
        at = _parse(entry.get("at"))
        if at is None:
            continue
        actor = str(entry.get("actor", ""))
        event = str(entry.get("event", ""))

        if actor == "intake":
            marks.setdefault("intake", at)
            opened = opened or at
        elif actor in _FIRST_EVIDENCE:
            marks.setdefault("first_evidence", at)
        elif actor == "critic":
            marks.setdefault("first_verdict", at)
        elif actor == "containment_planner":
            marks.setdefault("planned", at)
            # Each plan opens a gate; the next human decision closes it.
            first_gate = at
        elif _is_human(actor):
            marks.setdefault("first_human", at)
            decided = "Approved" in event or "Rejected" in event
            if first_gate is not None and decided:
                human_waits.append((first_gate, at))
                first_gate = None
        elif actor == "system" and event.startswith("Plan withdrawn"):
            # Nobody came, and the plan went stale waiting. That is still time
            # the incident spent blocked on a person — arguably the purest
            # example of it — so the gate closes here and the wait counts.
            if first_gate is not None:
                human_waits.append((first_gate, at))
                first_gate = None
        elif actor == "executor":
            marks.setdefault("contained", at)
        elif actor == "reporter":
            marks["reported"] = at  # last report wins — revisions supersede

    last = _parse(record.get("updated_at")) or (
        _parse(timeline[-1].get("at")) if timeline else None
    )
    closed = marks.get("reported") if str(record.get("status")) == "completed" else None

    # An incident still sitting at a gate is still accruing wait, and pretending
    # otherwise makes an unattended queue look free.
    if first_gate is not None and str(record.get("status")) == "awaiting_approval":
        human_waits.append((first_gate, datetime.now(UTC)))

    def delta(a: datetime | None, b: datetime | None) -> float | None:
        return (b - a).total_seconds() if a and b else None

    detected = _parse((record.get("alert") or {}).get("detected_at"))
    waiting = sum((b - a).total_seconds() for a, b in human_waits) or None
    total = delta(opened, closed or last)

    phases = [
        {
            "key": "ttd",
            "label": "Detection lag",
            "abbr": "TTD",
            "seconds": delta(detected, opened),
            "note": "alert timestamped to us receiving it",
        },
        {
            "key": "tta",
            "label": "Time to first evidence",
            "abbr": "TTA",
            "seconds": delta(opened, marks.get("first_evidence")),
            "note": "opened to the first specialist reporting",
        },
        {
            "key": "ttt",
            "label": "Time to triage",
            "abbr": "TTT",
            "seconds": delta(opened, marks.get("first_verdict")),
            "note": "opened to the first verdict",
        },
        {
            "key": "ttp",
            "label": "Time to a plan",
            "abbr": "TTP",
            "seconds": delta(opened, marks.get("planned")),
            "note": "opened to containment proposed",
        },
        {
            "key": "ttc",
            "label": "Time to contain",
            "abbr": "TTC",
            "seconds": delta(opened, marks.get("contained")),
            "note": "opened to the first action executed",
        },
        {
            "key": "ttr",
            "label": "Time to resolve",
            "abbr": "TTR",
            "seconds": total,
            "note": "opened to the published report" if closed else "opened to now — still running",
        },
    ]
    # Which agents were working inside each window. "Time to triage: 1m 08s" is
    # a number; "1m 08s, and enrichment and behavioral both ran" is an
    # explanation, and it is the difference between a metric you can act on and
    # one you can only report.
    bounds = {
        "ttd": (detected, opened),
        "tta": (opened, marks.get("first_evidence")),
        "ttt": (opened, marks.get("first_verdict")),
        "ttp": (opened, marks.get("planned")),
        "ttc": (opened, marks.get("contained")),
        "ttr": (opened, closed or last),
    }
    # Every window starts at `opened`, so the cumulative lists nest and the
    # later ones read as noise. What a reader wants from "time to contain" is
    # what happened *since* the previous mark, so each phase shows only the
    # agents it added.
    already: set[str] = set()
    for phase in phases:
        phase["value"] = humanise(phase["seconds"])
        actors = _actors_between(timeline, *bounds.get(phase["key"], (None, None)))
        phase["actors"] = actors
        phase["new_actors"] = [a for a in actors if a not in already]
        already.update(actors)

    machine = (total - waiting) if (total is not None and waiting) else total
    share = (waiting / total * 100) if (total and waiting) else 0.0

    return {
        "phases": [p for p in phases if p["seconds"] is not None],
        "missing": [p["abbr"] for p in phases if p["seconds"] is None],
        "total_seconds": total,
        "total": humanise(total),
        "waiting_seconds": waiting,
        "waiting": humanise(waiting),
        "machine": humanise(machine),
        # The headline claim of the whole product, as a number.
        "human_share": round(share),
        "open": closed is None,
        "gates": len(human_waits),
    }


def fleet(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Means across a set of incidents — the M in MTTR.

    Only completed incidents count. Averaging in a run that is still open drags
    the mean toward "however long ago someone forgot about it".
    """
    done = [r for r in records if str(r.get("status")) == "completed"]
    if not done:
        return {"count": 0, "phases": []}

    measured = [measure(r) for r in done]
    by_key: dict[str, list[float]] = {}
    labels: dict[str, tuple[str, str]] = {}
    for m in measured:
        for phase in m["phases"]:
            by_key.setdefault(phase["key"], []).append(float(phase["seconds"]))
            labels[phase["key"]] = (phase["label"], phase["abbr"])

    phases = []
    for key, values in by_key.items():
        label, abbr = labels[key]
        mean = sum(values) / len(values)
        phases.append(
            {
                "key": key,
                "label": label,
                # A single incident measures TTR; the mean across incidents is
                # the MTTR people actually mean when they say MTTR.
                "abbr": f"M{abbr}",
                "seconds": mean,
                "value": humanise(mean),
                "samples": len(values),
            }
        )

    waits = [m["waiting_seconds"] for m in measured if m["waiting_seconds"]]
    return {
        "count": len(done),
        "phases": sorted(phases, key=lambda p: p["seconds"]),
        "waiting": humanise(sum(waits) / len(waits)) if waits else "—",
        "human_share": round(sum(m["human_share"] for m in measured) / len(measured)),
    }


def questions(record: dict[str, Any]) -> dict[str, Any]:
    """What the investigation needed a human for, and whether it found out.

    `open_questions` is only what is outstanding right now, so a question that
    was answered leaves no trace there. The timeline keeps the asks, so the two
    together give both halves: everything ever asked, minus what is still open,
    is what got resolved.
    """
    asked: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in record.get("timeline") or []:
        event = str(entry.get("event", ""))
        if not event.startswith("Asked: "):
            continue
        text = event[len("Asked: ") :].strip()
        if text in seen:
            continue
        seen.add(text)
        asked.append({"question": text, "at": str(entry.get("at", ""))})

    still_open = {str(q).strip() for q in (record.get("open_questions") or [])}

    # Answers arrive as follow-up notes rather than as replies to a specific
    # question — nobody quotes the question back. Pairing them is guesswork, so
    # the notes are shown as the evidence that closed *something* rather than
    # falsely attributed to one question.
    answers = [
        {
            "at": str(n.get("at", "")),
            "by": str(n.get("by") or "unknown"),
            "note": str(n.get("note", "")),
        }
        for n in (record.get("pending_notes") or [])
    ]

    for item in asked:
        item["resolved"] = item["question"] not in still_open

    # A question the record still lists but that was never recorded as asked —
    # raised on the current pass, before the ask went out.
    for text in sorted(still_open - seen):
        asked.append({"question": text, "at": "", "resolved": False})

    return {
        "asked": asked,
        "resolved": sum(1 for q in asked if q["resolved"]),
        "open": sum(1 for q in asked if not q["resolved"]),
        "answers": answers,
    }
