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
from app.observability import RUNS_STARTED, concise_error, get_logger
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


async def _execute(thread_id: str, incident_id: str, payload: Any) -> None:
    """Drive the graph to its next stopping point: interrupt, completion, or error."""
    async with _sem():
        graph = get_graph()
        config = _config(thread_id)
        try:
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

        snapshot = await graph.aget_state(config)
        state = dict(snapshot.values or {})
        interrupts = _pending_interrupts(snapshot)

        if interrupts:
            await incidents.save_state(incident_id, state, status="awaiting_approval")
            await _notify(incident_id, "awaiting_approval", interrupt=interrupts[0])
            log.info("runner.awaiting_approval", incident_id=incident_id)
        else:
            await incidents.save_state(incident_id, state, status="completed")
            await _notify(incident_id, "completed")
            log.info(
                "runner.completed",
                incident_id=incident_id,
                severity=state.get("severity"),
                verdict=state.get("verdict"),
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
