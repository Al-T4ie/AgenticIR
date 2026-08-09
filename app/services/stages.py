"""Where an incident currently sits in the agent graph.

A status of `running` says an investigation is happening; it does not say
whether that means three specialists are mid-flight or the report is being
written, and those are ten seconds and two minutes of waiting respectively.
The graph is the thing the responder actually wants to see themselves on.

Position is derived from the timeline rather than from the checkpointer: the
timeline is already loaded with the record, and reading the graph state would
mean a second round trip to Postgres on every page view for information that is
one join away. Where the two could disagree — a node that started but has not
yet written its timeline entry — the timeline is a step behind, never wrong.
"""

from __future__ import annotations

import re
from typing import Any

# The spine, in execution order. `specialist` covers whichever of the three ran.
STAGES: list[tuple[str, str]] = [
    ("intake", "Intake"),
    ("supervisor", "Plan"),
    ("specialist", "Specialists"),
    ("critic", "Review"),
    ("containment", "Containment"),
    ("approval", "Approval"),
    ("execute", "Execute"),
    ("report", "Report"),
]

# Timeline actor -> stage. Specialists write under their own name.
_ACTOR_STAGE = {
    "intake": "intake",
    "supervisor": "supervisor",
    "triage": "specialist",
    "enrichment": "specialist",
    "behavioral": "specialist",
    "critic": "critic",
    "containment_planner": "containment",
    "executor": "execute",
    "reporter": "report",
}

_TERMINAL = {"completed", "failed"}


def _stage_of(actor: str) -> str:
    if actor.startswith("human:") or actor == "channel":
        return "approval"
    return _ACTOR_STAGE.get(actor, "")


def derive(record: dict[str, Any]) -> dict[str, Any]:
    """Mark each stage done, active, waiting, pending, skipped or failed."""
    full = record.get("timeline", []) or []
    status = str(record.get("status", "running"))

    # A revision runs the whole spine again. Scoping to the latest pass is the
    # difference between "execute already happened" and "execute is about to
    # happen again" — on a reopened incident the first reading is a lie, and it
    # is the reading a whole-timeline scan gives you.
    starts = [i for i, e in enumerate(full) if str(e.get("actor")) == "intake"]
    revision = max(len(starts) - 1, 0)
    timeline = full[starts[-1] :] if starts else full

    reached: set[str] = set()
    last = ""
    for entry in timeline:
        stage = _stage_of(str(entry.get("actor", "")))
        if stage:
            reached.add(stage)
            last = stage

    def _rounds(entries: list[dict[str, Any]]) -> int:
        return sum(
            1
            for e in entries
            if str(e.get("actor")) == "supervisor" and "dispatched" in str(e.get("event", ""))
        )

    rounds, total_rounds = _rounds(timeline), _rounds(full)

    order = [key for key, _ in STAGES]
    active = ""
    if status == "awaiting_approval":
        active = "approval"
    elif status not in _TERMINAL and last:
        # Running: the next stage after the last one that reported is in flight.
        nxt = order.index(last) + 1
        active = order[nxt] if nxt < len(order) else last
    elif status not in _TERMINAL:
        active = "intake"

    steps = []
    for key, label in STAGES:
        if key == active:
            state = "waiting" if status == "awaiting_approval" else "active"
        elif key in reached:
            state = "failed" if (status == "failed" and key == last) else "done"
        elif status in _TERMINAL:
            # Never reached and never will be — the gate when nothing needed
            # approving, execute when there was nothing to run.
            state = "skipped"
        else:
            state = "pending"
        steps.append({"key": key, "label": label, "state": state})

    by_key = {s["key"]: s["state"] for s in steps}
    return {
        "steps": steps,
        # The graph template asks for states by node name rather than iterating.
        "state_of": by_key.get,
        "active": active,
        "status": status,
        "rounds": rounds,
        "total_rounds": total_rounds,
        "revision": revision,
        "reached": sorted(reached),
    }


SPECIALISTS = ["triage", "enrichment", "behavioral"]

_DISPATCH = re.compile(r"Round (\d+): dispatched (.+?)(?:$|\.)")


def specialist_states(record: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Per-specialist state for the current pass, for drawing the fan-out.

    The linear strip collapses three parallel agents into one box, which hides
    the thing most worth seeing while a run is in flight: two came back and the
    third is still out. Each lane gets its own state here.
    """
    full = record.get("timeline", []) or []
    starts = [i for i, e in enumerate(full) if str(e.get("actor")) == "intake"]
    timeline = full[starts[-1] :] if starts else full

    out = {name: {"state": "unused", "runs": 0, "last": ""} for name in SPECIALISTS}
    dispatched: set[str] = set()

    for entry in timeline:
        actor = str(entry.get("actor", ""))
        event = str(entry.get("event", ""))
        if actor == "supervisor":
            match = _DISPATCH.search(event)
            if match:
                for name in (n.strip() for n in match.group(2).split(",")):
                    if name in out:
                        dispatched.add(name)
                        # Dispatched and not yet heard from — in flight until
                        # its own entry lands.
                        out[name]["state"] = "active"
        elif actor in out:
            out[actor]["runs"] += 1
            out[actor]["last"] = event
            out[actor]["state"] = "failed" if "failed" in event.lower() else "done"

    # A terminal incident has nothing in flight; anything still marked active
    # was dispatched into a run that ended before it reported.
    if str(record.get("status", "")) in _TERMINAL:
        for name in dispatched:
            if out[name]["state"] == "active":
                out[name]["state"] = "failed"
    return out


def specialist_detail(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Every specialist run on this incident, across all passes, oldest first."""
    out: list[dict[str, Any]] = []
    for entry in record.get("timeline", []) or []:
        actor = str(entry.get("actor", ""))
        if _ACTOR_STAGE.get(actor) != "specialist":
            continue
        event = str(entry.get("event", ""))
        out.append(
            {
                "specialist": actor,
                "failed": "failed" in event.lower(),
                "event": event,
                "at": str(entry.get("at", ""))[11:19],
            }
        )
    return out
