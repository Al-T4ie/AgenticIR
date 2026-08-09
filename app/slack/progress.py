"""One live status line per investigation, rewritten as the run progresses.

The first version of this posted a message per phase. Correct, and unreadable:
seventeen messages for one incident, which a responder mid-incident has no time
to scroll. The information was right; the delivery was a cost imposed on the
reader.

So there is exactly one narration message per run and it is edited in place.
It answers the only questions the thread needs to answer while work is in
flight — is it moving, how far in is it, and did anything fail — in about four
lines. Everything that matters afterwards lives in the report.

Two rules still hold: narration goes in the incident's *thread*, never the
channel; and it never raises, because a Slack outage must not fail a run.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from app.config import get_settings
from app.observability import get_logger
from app.services import incidents

log = get_logger(__name__)

_MAX_LINE = 2800


@dataclass
class _Live:
    """The evolving state of one run's status message."""

    channel: str = ""
    ts: str = ""
    rounds: dict[int, list[str]] = field(default_factory=dict)
    reviews: dict[int, str] = field(default_factory=dict)
    current_round: int = 0
    tail: str = ""
    done: bool = False
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


_live: dict[str, _Live] = {}
_CACHE_LIMIT = 256


def reset(incident_id: str) -> None:
    """Start a fresh status message — used when a revision reopens an incident."""
    _live.pop(incident_id, None)


# Kept for callers that used to invalidate a cached thread.
forget = reset


async def _slot(incident_id: str) -> _Live | None:
    """The live status for an incident, creating it on first use."""
    existing = _live.get(incident_id)
    if existing is not None:
        return existing

    record = await incidents.get_incident(incident_id)
    if record is None:
        return None
    channel = record.get("slack_channel") or ""
    thread_ts = record.get("slack_thread_ts") or ""
    if not channel or not thread_ts:
        return None

    if len(_live) >= _CACHE_LIMIT:
        _live.clear()
    slot = _Live(channel=channel, ts="")
    slot.tail = thread_ts  # thread root; the status message ts is filled on first post
    _live[incident_id] = slot
    return slot


async def _render(incident_id: str, slot: _Live, thread_ts: str) -> None:
    """Push the current state to Slack, creating the message if needed."""
    icon = ":white_check_mark:" if slot.done else ":hourglass_flowing_sand:"
    lines = []
    for rnd in sorted(slot.rounds):
        lines.append(f"*R{rnd}* " + " · ".join(slot.rounds[rnd]))
        if rnd in slot.reviews:
            lines.append(f"     ↳ {slot.reviews[rnd]}")
    if slot.tail and slot.tail != thread_ts:
        lines.append(slot.tail)

    body = f"{icon} " + ("\n".join(lines) if lines else "starting…")
    payload: list[dict[str, Any]] = [
        {"type": "section", "text": {"type": "mrkdwn", "text": body[:_MAX_LINE]}}
    ]

    from app.slack import notifier

    if slot.ts:
        if await notifier.update(slot.channel, slot.ts, text=body, blocks_payload=payload):
            return
        slot.ts = ""  # the message is gone; fall through and post a new one
    slot.ts = await notifier.post(
        slot.channel, text=body, blocks_payload=payload, thread_ts=thread_ts
    )


async def _touch(incident_id: str, mutate) -> None:
    """Apply a change to the live status and re-render. Never raises.

    Specialists run concurrently and all write here, so the read-modify-render
    cycle is serialised per incident — otherwise two finishing at once race and
    one of them vanishes from the line.
    """
    settings = get_settings()
    if not settings.slack_enabled or not settings.slack_progress_updates:
        return
    try:
        slot = await _slot(incident_id)
        if slot is None:
            return
        record = await incidents.get_incident(incident_id)
        thread_ts = (record or {}).get("slack_thread_ts") or ""
        if not thread_ts:
            return
        async with slot.lock:
            mutate(slot)
            await _render(incident_id, slot, thread_ts)
    except Exception as exc:  # noqa: BLE001 — narration is never worth failing a run for
        log.debug("progress.failed", incident_id=incident_id, error=str(exc))


async def emit(incident_id: str, text: str, *, context: str = "") -> None:
    """Post a standalone line in the thread — for things that are not run progress."""
    settings = get_settings()
    if not settings.slack_enabled or not settings.slack_progress_updates:
        return
    try:
        record = await incidents.get_incident(incident_id)
        channel = (record or {}).get("slack_channel") or ""
        thread_ts = (record or {}).get("slack_thread_ts") or ""
        if not channel or not thread_ts:
            return

        from app.slack import notifier

        payload: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": text[:_MAX_LINE]}}
        ]
        if context:
            payload.append(
                {"type": "context", "elements": [{"type": "mrkdwn", "text": context[:1000]}]}
            )
        await notifier.post(
            channel, text=text[:_MAX_LINE], blocks_payload=payload, thread_ts=thread_ts
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("progress.emit_failed", incident_id=incident_id, error=str(exc))


# ── Phase updates ────────────────────────────────────────────────────────────


async def planning(incident_id: str, round_no: int, specialists: list[str], reasoning: str) -> None:
    def mutate(slot: _Live) -> None:
        slot.current_round = round_no
        if specialists:
            slot.rounds[round_no] = [f"{s} ⋯" for s in specialists]
        else:
            slot.tail = "_no further investigation needed_"

    await _touch(incident_id, mutate)


async def specialist_started(incident_id: str, specialist: str, objective: str) -> None:
    """No-op: the round line already names every specialist it dispatched."""
    return


async def specialist_finished(
    incident_id: str, specialist: str, count: int, seconds: float, gaps: str = ""
) -> None:
    await _touch(incident_id, _mark(specialist, f"{specialist} ✓{count} ({seconds:.0f}s)"))


async def specialist_failed(incident_id: str, specialist: str, error: str) -> None:
    await _touch(incident_id, _mark(specialist, f"{specialist} ✗"))


def _mark(specialist: str, replacement: str):
    """Replace this specialist's entry in the round it is running in."""

    def mutate(slot: _Live) -> None:
        entries = slot.rounds.setdefault(slot.current_round or 1, [])
        for i, entry in enumerate(entries):
            if entry.startswith(f"{specialist} ") and entry.endswith("⋯"):
                entries[i] = replacement
                return
        entries.append(replacement)

    return mutate


async def reviewed(
    incident_id: str, verdict: str, severity: str, needs_more: bool, feedback: str
) -> None:
    def mutate(slot: _Live) -> None:
        tail = "another round" if needs_more else "closed"
        slot.reviews[slot.current_round or 1] = f"{verdict.replace('_', ' ')} · {severity} · {tail}"

    await _touch(incident_id, mutate)


async def containment_planned(incident_id: str, actions: list[dict[str, Any]]) -> None:
    def mutate(slot: _Live) -> None:
        slot.done = True
        if not actions:
            slot.tail = ":shield: no containment proposed"
            return
        needing = sum(1 for a in actions if a.get("requires_approval"))
        slot.tail = f":shield: {len(actions)} action(s)" + (
            f" · *{needing} need approval*" if needing else " · auto-approved"
        )

    await _touch(incident_id, mutate)


async def executed(incident_id: str, count: int, failures: int) -> None:
    if not count and not failures:
        return

    def mutate(slot: _Live) -> None:
        slot.done = True
        slot.tail = f":gear: executed {count}" + (f", {failures} failed" if failures else "")

    await _touch(incident_id, mutate)


async def ask_humans(incident_id: str, questions: list[str]) -> None:
    """Put the gaps only a human can close in front of the humans.

    These are the questions the investigation cannot answer with any amount of
    further automated work — ownership, intent, whether something was expected.
    Left inside the report they read as caveats and get skimmed past; asked
    directly, they get answered, and the answer is what moves the verdict.
    """
    if not questions:
        return
    numbered = "\n".join(f"{i}. {q}" for i, q in enumerate(questions[:3], 1))
    await emit(
        incident_id,
        f":question: *Need from you*\n{numbered}",
        context="Reply in this thread — I'll fold the answers in and re-assess.",
    )
