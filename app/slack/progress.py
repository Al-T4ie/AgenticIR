"""Live narration of an investigation into its Slack thread.

Without this the analyst sees an acknowledgement, then silence for a couple of
minutes, then a finished report — no way to tell a working investigation from a
wedged one. Each phase of the graph posts a short line here instead, so the
thread reads as a running account of what the agents are doing and why.

Two rules govern everything in this module:

* it posts into the incident's *thread*, never the channel, so narration stays
  collapsed behind the root message and does not flood the channel; and
* it never raises. A Slack outage must not fail an investigation, so every
  failure path degrades to a log line.
"""

from __future__ import annotations

from typing import Any

from app.config import get_settings
from app.observability import get_logger
from app.services import incidents

log = get_logger(__name__)

# incident_id -> (channel, thread_ts). Only populated once a thread exists, so a
# slash-command incident (whose thread ts is attached moments after the record
# is created) is not cached as thread-less for the rest of its life.
_thread_cache: dict[str, tuple[str, str]] = {}
_CACHE_LIMIT = 512

_MAX_LINE = 2800


async def _destination(incident_id: str) -> tuple[str, str] | None:
    """Resolve (channel, thread_ts) for an incident, or None if it has no thread."""
    cached = _thread_cache.get(incident_id)
    if cached:
        return cached

    record = await incidents.get_incident(incident_id)
    if record is None:
        return None
    channel = record.get("slack_channel") or ""
    thread_ts = record.get("slack_thread_ts") or ""
    if not channel or not thread_ts:
        return None

    if len(_thread_cache) >= _CACHE_LIMIT:
        _thread_cache.clear()
    _thread_cache[incident_id] = (channel, thread_ts)
    return channel, thread_ts


def forget(incident_id: str) -> None:
    """Drop a cached thread — used when an incident's thread is re-attached."""
    _thread_cache.pop(incident_id, None)


async def emit(incident_id: str, text: str, *, context: str = "") -> None:
    """Post one progress line into the incident thread. Never raises."""
    settings = get_settings()
    if not settings.slack_enabled or not settings.slack_progress_updates:
        return

    try:
        destination = await _destination(incident_id)
        if destination is None:
            return
        channel, thread_ts = destination

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
    except Exception as exc:  # noqa: BLE001 — narration is never worth failing a run for
        log.debug("progress.emit_failed", incident_id=incident_id, error=str(exc))


# ── Phase helpers ────────────────────────────────────────────────────────────
# Kept here rather than inline in the nodes so the wording stays consistent and
# a node only has to describe what it did, not how to say it.


async def planning(incident_id: str, round_no: int, specialists: list[str], reasoning: str) -> None:
    if specialists:
        head = (
            f":brain: *Round {round_no}* — dispatching "
            f"{', '.join(f'`{s}`' for s in specialists)} in parallel"
        )
    else:
        head = f":brain: *Round {round_no}* — no further investigation needed"
    await emit(incident_id, head, context=_trim(reasoning))


async def specialist_started(incident_id: str, specialist: str, objective: str) -> None:
    await emit(
        incident_id,
        f":mag: `{specialist}` started",
        context=_trim(objective, 300),
    )


async def specialist_finished(
    incident_id: str, specialist: str, count: int, seconds: float, gaps: str = ""
) -> None:
    await emit(
        incident_id,
        f":white_check_mark: `{specialist}` reported *{count}* finding(s) in {seconds:.0f}s",
        context=_trim(f"gaps: {gaps}", 300) if gaps else "",
    )


async def specialist_failed(incident_id: str, specialist: str, error: str) -> None:
    await emit(incident_id, f":x: `{specialist}` failed", context=_trim(error, 300))


async def reviewed(
    incident_id: str, verdict: str, severity: str, needs_more: bool, feedback: str
) -> None:
    tail = "requesting another round" if needs_more else "closing the investigation"
    await emit(
        incident_id,
        f":balance_scale: *Review* — {verdict.replace('_', ' ')} at *{severity}* severity, {tail}",
        context=_trim(feedback, 400) if needs_more else "",
    )


async def containment_planned(incident_id: str, actions: list[dict[str, Any]]) -> None:
    if not actions:
        await emit(incident_id, ":shield: No containment actions proposed")
        return
    listed = ", ".join(f"`{a.get('action')}` → {a.get('target')}" for a in actions[:5])
    needing = sum(1 for a in actions if a.get("requires_approval"))
    await emit(
        incident_id,
        f":shield: Proposed *{len(actions)}* containment action(s): {listed}",
        context=f"{needing} require human approval" if needing else "all auto-approved",
    )


async def executed(incident_id: str, count: int, failures: int) -> None:
    if not count and not failures:
        return
    await emit(
        incident_id,
        f":gear: Executed *{count}* action(s)" + (f", *{failures}* failed" if failures else ""),
    )


def _trim(text: str, limit: int = 500) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
