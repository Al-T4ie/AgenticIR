"""The ten-minute catch-up.

An incident that resolves in fifteen minutes needs no catch-up: the thread is
the catch-up. One that runs for five hours does, because the people working it
are not watching it — they are in a call, or asleep, or on the third thing since
they last looked, and what they need on returning is not a scrollback of forty
status edits but four lines telling them what changed, what is stuck, and
whether anything wants them.

Two rules keep it from becoming the thing everyone mutes:

* it says what happened **since the last one**, not what is true in general —
  a digest that restates the incident every ten minutes is a digest nobody
  finishes reading;
* it does not post when there is nothing to report and nothing is blocked.
  Silence is information: it means the machine is working and needs nothing.

What is blocking gets repeated every time, deliberately. An approval nobody has
looked at in two hours is the single most useful thing the message can say, and
saying it once at minute ten and never again is how it stays unlooked-at.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.config import get_settings
from app.observability import get_logger
from app.services import modes as modes_mod
from app.services.timings import humanise

log = get_logger(__name__)

# Actors whose timeline entries are the machine narrating itself. Worth counting
# and summarising; not worth quoting line by line into a catch-up.
_MAX_LINES = 6


def _parse(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def since_window(record: dict[str, Any]) -> datetime | None:
    """Where the last catch-up left off, or the start of the incident."""
    return _parse(record.get("last_digest_at")) or _parse(record.get("created_at"))


def _recent(record: dict[str, Any], since: datetime | None) -> list[dict[str, Any]]:
    if since is None:
        return list(record.get("timeline") or [])
    out = []
    for entry in record.get("timeline") or []:
        at = _parse(entry.get("at"))
        if at is not None and at > since:
            out.append(entry)
    return out


def _gate_age(record: dict[str, Any], now: datetime) -> float | None:
    """Seconds the current approval has been waiting, from when it was proposed."""
    if record.get("status") != "awaiting_approval":
        return None
    proposed = None
    for entry in record.get("timeline") or []:
        if str(entry.get("actor")) == "containment_planner":
            proposed = _parse(entry.get("at")) or proposed
    if proposed is None:
        proposed = _parse(record.get("updated_at"))
    return (now - proposed).total_seconds() if proposed else None


def compose(record: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    """Build the catch-up. `post` is False when there is nothing worth saying."""
    now = now or datetime.now(UTC)
    opened = _parse(record.get("created_at"))
    since = since_window(record)
    events = _recent(record, since)

    mode = modes_mod.get(record.get("mode"))
    pending = [a for a in (record.get("containment_actions") or []) if a.get("requires_approval")]
    questions = [str(q) for q in (record.get("open_questions") or []) if str(q).strip()]
    notes = record.get("pending_notes") or []
    gate_age = _gate_age(record, now)

    blocked = bool(pending and record.get("status") == "awaiting_approval") or bool(questions)
    if not events and not blocked:
        return {"post": False}

    elapsed = humanise((now - opened).total_seconds()) if opened else "—"
    gap = humanise((now - since).total_seconds()) if since else "—"

    header = (
        f":clock10: *Catch-up* · `{record.get('id')}` · {elapsed} in · "
        f"{mode.label.lower()} · {record.get('status')}"
    )

    verdict = str(record.get("verdict") or "inconclusive").replace("_", " ")
    confidence = float(record.get("confidence") or 0.0)
    standing = (
        f"*{verdict}* at *{record.get('severity', 'unknown')}* severity · "
        f"confidence {confidence:.0%} · {len(record.get('findings') or [])} finding(s)"
    )

    sections: list[str] = [standing]

    # ── What moved ──
    if events:
        by_actor: dict[str, list[str]] = {}
        for entry in events:
            by_actor.setdefault(str(entry.get("actor", "?")), []).append(
                str(entry.get("event", ""))
            )
        lines = []
        for actor, said in list(by_actor.items())[:_MAX_LINES]:
            # The last thing each actor said is the current one; the earlier
            # ones are how it got there, and the count carries that.
            more = f" _(+{len(said) - 1} more)_" if len(said) > 1 else ""
            lines.append(f"• *{actor}* — {said[-1][:180]}{more}")
        hidden = len(by_actor) - len(lines)
        if hidden > 0:
            lines.append(f"• _…and {hidden} other actor(s)_")
        sections.append(f"*Since the last check-in ({gap} ago)*\n" + "\n".join(lines))
    else:
        sections.append(f"*Since the last check-in ({gap} ago)* — nothing new.")

    # ── What is stuck ──
    stuck: list[str] = []
    if pending and record.get("status") == "awaiting_approval":
        waited = humanise(gate_age) if gate_age is not None else "—"
        stuck.append(
            f"• :hourglass: *{len(pending)} action(s) waiting on approval* for {waited} — "
            + ", ".join(f"`{a.get('action', '?')}` on {a.get('target', '?')}" for a in pending[:4])
        )
    if questions:
        stuck.append(
            f"• :question: *{len(questions)} question(s) unanswered*\n"
            + "\n".join(f"    {i}. {q[:200]}" for i, q in enumerate(questions[:3], 1))
        )
    if notes:
        stuck.append(f"• :inbox_tray: {len(notes)} note(s) queued, folding in when this settles")
    if stuck:
        sections.append("*Waiting on you*\n" + "\n".join(stuck))

    # ── What happens next, given the posture ──
    if not mode.investigates:
        next_up = "Nothing, unless you ask — I'm in spectator mode."
    elif pending and record.get("status") == "awaiting_approval":
        next_up = "Holding for your decision. New information will supersede this plan."
    else:
        next_up = "Continuing to work it and folding in whatever lands here."
    sections.append(f"_{next_up}_")

    blocks = [
        {"type": "context", "elements": [{"type": "mrkdwn", "text": header}]},
        {"type": "section", "text": {"type": "mrkdwn", "text": "\n\n".join(sections)[:2900]}},
    ]
    return {
        "post": True,
        "text": f"Catch-up on {record.get('id')} — {elapsed} in, {len(events)} update(s)",
        "blocks": blocks,
        "events": len(events),
        "blocked": blocked,
    }


async def post(record: dict[str, Any]) -> bool:
    """Publish the catch-up. Returns whether anything was actually said.

    A digest is a courtesy, never a run-critical step, so every failure path
    here degrades to False and the incident carries on unaffected.
    """
    settings = get_settings()
    if not settings.slack_enabled:
        return False
    channel = str(record.get("slack_channel") or "")
    if not channel:
        return False

    built = compose(record)
    if not built.get("post"):
        return False

    try:
        from app.slack import notifier

        ts = await notifier.post(
            channel,
            text=str(built["text"]),
            blocks_payload=list(built["blocks"]),
            # In a war room there is no thread — the room is the thread.
            thread_ts=str(record.get("slack_thread_ts") or ""),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("digest.post_failed", incident_id=record.get("id"), error=str(exc))
        return False
    return bool(ts)
