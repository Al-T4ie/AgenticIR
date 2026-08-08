"""Run orchestration: start investigations, pause on HITL, resume them later.

Runs execute as background asyncio tasks so HTTP callers (Slack's 3-second
budget, n8n webhooks) return immediately. Durability comes from the LangGraph
checkpointer, not from this process — if the container dies mid-run, the thread
can be resumed from its last checkpoint.
"""

from __future__ import annotations

import asyncio
from typing import Any

from langgraph.types import Command

from app.config import get_settings
from app.graph.builder import get_graph
from app.graph.state import new_state
from app.observability import ACTIVE_RUNS, RUNS_STARTED, concise_error, get_logger
from app.services import incidents

log = get_logger(__name__)

# Bounds concurrent investigations so a burst of SIEM alerts can't exhaust
# memory or blow through the LLM rate limit.
_MAX_CONCURRENT_RUNS = 8
_semaphore: asyncio.Semaphore | None = None
_tasks: set[asyncio.Task] = set()


def _sem() -> asyncio.Semaphore:
    global _semaphore
    if _semaphore is None:
        _semaphore = asyncio.Semaphore(_MAX_CONCURRENT_RUNS)
    return _semaphore


def _config(thread_id: str) -> dict[str, Any]:
    return {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": 60,
    }


def _spawn(coro) -> asyncio.Task:
    """Fire-and-forget with a strong reference, so the task isn't GC'd mid-flight."""
    task = asyncio.create_task(coro)
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return task


async def start_investigation(
    *,
    alert: dict[str, Any] | None = None,
    question: str = "",
    source: str = "api",
    slack_channel: str = "",
    slack_thread_ts: str = "",
) -> dict[str, Any]:
    """Register an incident and kick off the graph in the background."""
    incident_id = incidents.new_incident_id()
    thread_id = incident_id  # 1:1 — a Slack thread maps to exactly one incident

    record = await incidents.create_incident(
        incident_id=incident_id,
        thread_id=thread_id,
        source=source,
        alert=alert or {},
        question=question,
        slack_channel=slack_channel,
        slack_thread_ts=slack_thread_ts,
    )
    RUNS_STARTED.labels(source=source).inc()

    # An alert routed to a channel but not to a thread — a SIEM webhook, an API
    # caller, a slash command — has nowhere to narrate, so it would go silent
    # until the final report. Open the thread first by acknowledging in the
    # channel, and adopt that message as the incident's thread root.
    if slack_channel and not slack_thread_ts:
        slack_thread_ts = await _open_thread(incident_id, slack_channel, record["title"])
        if slack_thread_ts:
            record["slack_thread_ts"] = slack_thread_ts

    initial = new_state(
        incident_id=incident_id,
        thread_id=thread_id,
        source=source,
        alert=alert or {},
        question=question,
        slack_channel=slack_channel,
        slack_thread_ts=slack_thread_ts,
    )
    _spawn(_execute(thread_id, incident_id, initial))
    log.info("runner.started", incident_id=incident_id, source=source)
    return record


async def _open_thread(incident_id: str, channel: str, title: str) -> str:
    """Post the acknowledgement and make it the incident's thread. Never raises."""
    if not get_settings().slack_enabled:
        return ""
    try:
        from app.slack import notifier, progress

        ts = await notifier.acknowledge(channel, "", incident_id, title)
        if not ts:
            return ""
        await incidents.attach_slack_thread(incident_id, channel, ts)
        progress.forget(incident_id)  # it may have been cached as thread-less
        return ts
    except Exception as exc:  # noqa: BLE001 — an un-narrated run still beats no run
        log.error("runner.open_thread_failed", incident_id=incident_id, error=str(exc))
        return ""


async def resume_investigation(incident_id: str, decision: dict[str, Any]) -> dict[str, Any] | None:
    """Resume a run parked on an approval interrupt."""
    record = await incidents.get_incident(incident_id)
    if record is None:
        return None
    if record["status"] != "awaiting_approval":
        log.warning("runner.resume_wrong_status", incident_id=incident_id, status=record["status"])
        return record

    await incidents.set_status(incident_id, "running")
    _spawn(_execute(record["thread_id"], incident_id, Command(resume=decision)))
    log.info("runner.resumed", incident_id=incident_id, approver=decision.get("approver"))
    return record


async def follow_up_investigation(
    incident_id: str,
    note: str,
    *,
    reported_by: str = "",
) -> str:
    """Fold late-arriving information into an incident and re-assess it.

    Intelligence does not stop arriving when a report is posted — an analyst
    adds context, a second alert lands, someone identifies the host. Rather than
    opening a disconnected incident, this re-enters the *same* graph thread. The
    checkpointer still holds the previous findings, and `findings`/`timeline`
    are additive, so the re-run builds on what is already known instead of
    starting from nothing, and the revised report lands in the same Slack thread.

    Returns the disposition: "revising", "queued", "awaiting_approval" or
    "unknown" — callers use it to word their reply.
    """
    record = await incidents.get_incident(incident_id)
    if record is None:
        return "unknown"

    status = record["status"]
    if status in {"running", "awaiting_approval"}:
        # The graph cannot be re-entered mid-run, and re-planning underneath a
        # pending approval would invalidate the very actions being decided on.
        # Neither is a reason to reject the information: telemetry does not wait
        # for a decision, and an approver is exactly who should see it. Park it
        # and apply it the moment the incident is idle again.
        depth = await incidents.queue_note(incident_id, note, reported_by)
        log.info("runner.note_queued", incident_id=incident_id, status=status, depth=depth)
        return "queued" if status == "running" else "queued_for_approval"

    thread_id = record["thread_id"]
    snapshot = await get_graph().aget_state(_config(thread_id))
    values = dict(snapshot.values or {})

    revision = int(values.get("revision", 0) or 0) + 1
    alert = dict(values.get("alert", {}) or {})
    notes = list(alert.get("follow_up_notes", []) or [])
    notes.append({"at": _now(), "by": reported_by, "note": note})

    attribution = f"<@{reported_by}>" if reported_by else "an analyst"
    await incidents.set_status(incident_id, "running")
    RUNS_STARTED.labels(source="slack-followup").inc()

    _spawn(
        _execute(
            thread_id,
            incident_id,
            {
                "alert": {**alert, "follow_up_notes": notes},
                "question": f"{values.get('question', '')}\n\nFOLLOW-UP: {note}".strip(),
                "plan": [],
                "approval": {},
                "needs_more_work": True,
                "revision": revision,
                # Consumed by the supervisor on the first round, so the re-run
                # chases the new information rather than repeating itself.
                "critic_feedback": (
                    f"New information arrived from {attribution} after the previous "
                    f"assessment was published: {note}\n\n"
                    "Re-evaluate the incident in light of it. Investigate what this "
                    "changes; do not simply repeat the earlier conclusions."
                ),
                "timeline": [
                    {
                        "at": _now(),
                        "actor": f"human:{reported_by}" if reported_by else "channel",
                        "event": f"Revision {revision} triggered by new information: {note[:300]}",
                    }
                ],
            },
        )
    )
    log.info("runner.follow_up", incident_id=incident_id, revision=revision, by=reported_by)
    return "revising"


def _now() -> str:
    from app.graph.nodes.intake import now_iso

    return now_iso()


async def _execute(thread_id: str, incident_id: str, payload: Any) -> None:
    """Drive the graph to its next stopping point: interrupt, completion, or error."""
    async with _sem():
        graph = get_graph()
        config = _config(thread_id)
        ACTIVE_RUNS.inc()
        try:
            # payload None resumes from the stored checkpoint without injecting
            # new input — how an interrupted run is picked back up.
            await graph.ainvoke(payload, config=config)
        except Exception as exc:
            log.exception("runner.failed", incident_id=incident_id, error=str(exc))
            await incidents.save_state(
                incident_id,
                {"errors": [f"run failed: {concise_error(exc)}"]},
                status="failed",
            )
            await _notify(incident_id, "failed")
            return
        finally:
            ACTIVE_RUNS.dec()

        snapshot = await graph.aget_state(config)
        state = dict(snapshot.values or {})
        interrupts = _pending_interrupts(snapshot)

        # Read what was already asked before the new state overwrites it, so the
        # same three questions are not re-posted after every revision.
        previous = await incidents.get_incident(incident_id)
        asked_before = set((previous or {}).get("open_questions", []) or [])

        if interrupts:
            await incidents.save_state(incident_id, state, status="awaiting_approval")
            await _label_revision(incident_id, state)
            await _notify(incident_id, "awaiting_approval", interrupt=interrupts[0])
            await _ask_open_questions(incident_id, state, asked_before)
            log.info("runner.awaiting_approval", incident_id=incident_id)
        else:
            await incidents.save_state(incident_id, state, status="completed")
            await _label_revision(incident_id, state)
            await _notify(incident_id, "completed")
            await _ask_open_questions(incident_id, state, asked_before)
            # Anything that arrived while this was in flight applies now.
            await _apply_pending(incident_id)
            log.info(
                "runner.completed",
                incident_id=incident_id,
                severity=state.get("severity"),
                verdict=state.get("verdict"),
            )


async def _ask_open_questions(
    incident_id: str, state: dict[str, Any], asked_before: set[str]
) -> None:
    """Surface the gaps only a human can close — once each, not every round."""
    questions = [q for q in (state.get("open_questions") or []) if q not in asked_before]
    if not questions:
        return
    from app.slack import progress

    await progress.ask_humans(incident_id, questions)
    log.info("runner.asked_humans", incident_id=incident_id, questions=len(questions))


async def _apply_pending(incident_id: str) -> None:
    """Fold in information that arrived while the incident was busy.

    Everything queued is applied as one revision rather than one run each — five
    notes that landed during a two-minute investigation are five facts about the
    same incident, not five reasons to re-investigate it.
    """
    queued = await incidents.drain_notes(incident_id)
    if not queued:
        return

    note = "\n".join(f"- ({n.get('by') or 'unknown'}) {n.get('note', '')}" for n in queued)
    reporters = sorted({str(n.get("by") or "") for n in queued if n.get("by")})
    log.info("runner.applying_pending", incident_id=incident_id, count=len(queued))
    await follow_up_investigation(
        incident_id,
        f"Information received while the investigation was in progress:\n{note}",
        reported_by=", ".join(reporters),
    )


async def _label_revision(incident_id: str, state: dict[str, Any]) -> None:
    """Announce a re-assessment before its outcome lands in the thread.

    Whatever the run stops on — a finished report or a fresh approval request —
    it must not read as a duplicate that silently contradicts the first one.
    """
    revision = int(state.get("revision", 0) or 0)
    if not revision:
        return

    from app.slack import progress

    await progress.emit(
        incident_id,
        f":arrows_counterclockwise: *Revision {revision}* — supersedes the above.",
    )


def _pending_interrupts(snapshot: Any) -> list[Any]:
    """Read pending interrupts across LangGraph versions.

    Newer releases expose `snapshot.interrupts`; older ones only surface them on
    the pending task tuples.
    """
    found = list(getattr(snapshot, "interrupts", None) or [])
    if found:
        return [getattr(i, "value", i) for i in found]
    for task in getattr(snapshot, "tasks", None) or []:
        for intr in getattr(task, "interrupts", None) or []:
            found.append(getattr(intr, "value", intr))
    return found


async def _notify(incident_id: str, event: str, interrupt: Any = None) -> None:
    """Push the outcome to Slack. Never let a notification failure fail the run."""
    if not get_settings().slack_enabled:
        return
    try:
        from app.slack.notifier import notify_incident

        await notify_incident(incident_id, event, interrupt=interrupt)
    except Exception as exc:
        log.error("runner.notify_failed", incident_id=incident_id, event=event, error=str(exc))


async def get_thread_state(thread_id: str) -> dict[str, Any]:
    snapshot = await get_graph().aget_state(_config(thread_id))
    return {
        "values": dict(snapshot.values or {}),
        "next": list(snapshot.next or []),
        "interrupts": _pending_interrupts(snapshot),
    }


async def drain(timeout: float = 30.0) -> None:  # noqa: ASYNC109
    """Give in-flight runs a chance to checkpoint before shutdown.

    The timeout is a shutdown budget handed to `asyncio.wait`, not a
    cancellation deadline — runs that overrun it keep their last checkpoint and
    are resumable, so `asyncio.timeout` would be the wrong tool.
    """
    if not _tasks:
        return
    log.info("runner.draining", in_flight=len(_tasks))
    await asyncio.wait(set(_tasks), timeout=timeout)


# ── Recovery after a restart ─────────────────────────────────────────────────
# The checkpointer makes state durable, but nothing restarts the *execution*.
# A run interrupted mid-flight (deploy, OOM, crash) otherwise sits in "running"
# for ever with an intact checkpoint that nobody picks up — durable in storage,
# abandoned in practice.
_RECOVERY_LOCK_KEY = 8_291_774_120_355_001


async def recover_interrupted(limit: int = 25) -> int:
    """Resume investigations left mid-flight by a previous process.

    Guarded by a Postgres advisory lock so that with several web workers exactly
    one performs recovery — otherwise every worker would resume the same thread
    concurrently and duplicate the work.
    """
    from sqlalchemy import text

    from app.db.session import session_scope

    async with session_scope() as session:
        got = await session.execute(
            text("SELECT pg_try_advisory_lock(:k)"), {"k": _RECOVERY_LOCK_KEY}
        )
        if not got.scalar():
            log.info("runner.recovery_skipped", reason="another worker holds the lock")
            return 0

    stale = await incidents.list_incidents(limit=limit, status="running")
    if not stale:
        return 0

    resumed = 0
    for row in stale:
        thread_id = row["thread_id"]
        try:
            snapshot = await get_graph().aget_state(_config(thread_id))
        except Exception as exc:
            log.warning("runner.recovery_state_failed", incident_id=row["id"], error=str(exc))
            continue

        # `next` names the node the graph would run. Empty means it actually
        # finished and only the projection is stale, so just correct the record.
        if not list(snapshot.next or []):
            await incidents.save_state(row["id"], dict(snapshot.values or {}), status="completed")
            continue

        log.info("runner.recovering", incident_id=row["id"], next=list(snapshot.next))
        _spawn(_execute(thread_id, row["id"], None))
        resumed += 1

    log.info("runner.recovery_complete", resumed=resumed, examined=len(stale))
    return resumed
