"""Turn an incident's timeline into something you can look at.

The stored timeline is a flat list of point events — actor, instant, sentence.
Read top to bottom it answers "what happened" and almost nothing else. The
questions an analyst actually has after a run are shaped differently: where did
the five minutes go, what ran at the same time as what, how many rounds did the
reviewer demand, and which pass produced the conclusion.

Those are all answers about *duration and overlap*, which a list cannot show.
So this reconstructs spans from the point events: a supervisor dispatch names
the specialists it started, and each specialist's own event marks when it
finished, which bounds the work between them. Everything else stays a marker.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

# "Round 2: dispatched enrichment, behavioral"
_DISPATCH = re.compile(r"Round (\d+): dispatched (.+?)(?:$|\.)")

# Pipeline order, so lanes read top-to-bottom the way the graph runs rather than
# in whatever order the actors happen to appear.
_LANE_ORDER = [
    "intake",
    "supervisor",
    "triage",
    "enrichment",
    "behavioral",
    "critic",
    "containment_planner",
    "executor",
    "reporter",
]

_KIND = {
    "intake": "intake",
    "supervisor": "plan",
    "triage": "work",
    "enrichment": "work",
    "behavioral": "work",
    "critic": "review",
    "containment_planner": "action",
    "executor": "action",
    "reporter": "intake",
}


def _parse(stamp: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(stamp))
    except (TypeError, ValueError):
        return None


def _kind(actor: str) -> str:
    if actor.startswith("human:") or actor == "channel":
        return "human"
    return _KIND.get(actor, "work")


def _lane_rank(actor: str) -> tuple[int, str]:
    if actor in _LANE_ORDER:
        return (_LANE_ORDER.index(actor), actor)
    if actor.startswith("human:") or actor == "channel":
        # Humans sit between the planner and the executor: they are the gate.
        return (_LANE_ORDER.index("containment_planner") + 0.5, actor)  # type: ignore[return-value]
    return (len(_LANE_ORDER), actor)


def build(timeline: list[dict[str, Any]]) -> dict[str, Any]:
    """Reshape a stored timeline into lanes, spans and markers.

    Returns an empty structure rather than raising when the timeline is missing
    or malformed — a broken visualisation must not take the incident page down.
    """
    events: list[dict[str, Any]] = []
    for entry in timeline or []:
        at = _parse(entry.get("at", ""))
        if at is None:
            continue
        events.append(
            {
                "at": at,
                "actor": str(entry.get("actor", "unknown")),
                "event": str(entry.get("event", "")),
            }
        )
    if not events:
        return {"empty": True, "lanes": [], "runs": [], "ticks": [], "total": 0.0}

    events.sort(key=lambda e: e["at"])
    origin = events[0]["at"]
    total = max((e["at"] - origin).total_seconds() for e in events) or 1.0

    def offset(when: datetime) -> float:
        return (when - origin).total_seconds()

    # ── Runs. A second `intake` means the incident was reopened; each run is
    # banded separately so a revision reads as a distinct pass, not more of the
    # same one.
    runs: list[dict[str, Any]] = []
    for event in events:
        if event["actor"] == "intake":
            runs.append({"start": offset(event["at"]), "end": total, "label": ""})
    if not runs:
        runs = [{"start": 0.0, "end": total, "label": ""}]
    for i, run in enumerate(runs):
        if i + 1 < len(runs):
            run["end"] = runs[i + 1]["start"]
        run["label"] = "initial" if i == 0 else f"revision {i}"

    # ── Spans. A dispatch names who it started; that specialist's next event
    # ends the span. Anything still open at the end of the run is unfinished.
    spans: dict[str, list[dict[str, Any]]] = {}
    for i, event in enumerate(events):
        if event["actor"] != "supervisor":
            continue
        match = _DISPATCH.search(event["event"])
        if not match:
            continue
        round_no = match.group(1)
        names = [n.strip() for n in match.group(2).split(",") if n.strip()]
        started = offset(event["at"])
        for name in names:
            finish = next(
                (offset(e["at"]) for e in events[i + 1 :] if e["actor"] == name),
                None,
            )
            failed = False
            if finish is not None:
                closing = next(e for e in events[i + 1 :] if e["actor"] == name)
                failed = "failed" in closing["event"].lower()
            spans.setdefault(name, []).append(
                {
                    "start": started,
                    "end": finish if finish is not None else total,
                    "round": round_no,
                    "open": finish is None,
                    "failed": failed,
                }
            )

    # A specialist's own event is the end of its span, not a separate dot.
    spanned_actors = set(spans)
    marks: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        actor = event["actor"]
        if actor in spanned_actors:
            continue
        marks.setdefault(actor, []).append({"at": offset(event["at"]), "label": event["event"]})

    lanes = []
    for actor in sorted(set(spans) | set(marks), key=_lane_rank):
        label = actor.replace("human:", "").replace("_", " ")
        lanes.append(
            {
                # The gutter is fixed width; a long name silently overruns it
                # and renders clipped, which reads as a corrupt chart.
                "actor": label if len(label) <= 21 else label[:20] + "…",
                "kind": _kind(actor),
                "spans": spans.get(actor, []),
                "marks": marks.get(actor, []),
            }
        )

    return {
        "empty": False,
        "lanes": lanes,
        "runs": runs,
        "ticks": _ticks(total),
        "total": total,
        "started_at": origin.isoformat(),
    }


def _ticks(total: float) -> list[dict[str, Any]]:
    """Axis marks at a round interval, roughly six across whatever the span is."""
    for step in (10, 15, 30, 60, 120, 300, 600, 1800, 3600):
        if total / step <= 8:
            break
    out = []
    value = 0.0
    while value <= total:
        out.append({"at": value, "label": _human(value)})
        value += step
    return out


def _human(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f}s"
    minutes, rest = divmod(int(seconds), 60)
    return f"{minutes}m" if rest == 0 else f"{minutes}m{rest:02d}"
