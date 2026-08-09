"""The caretaker for incidents between runs.

Everything else in this system is reactive: an alert arrives and the graph runs,
a human replies and the poller reads it, an approval lands and the run resumes.
That is a complete design for an incident that finishes in one sitting, and an
incomplete one for an incident that lasts an afternoon — because the interesting
failures of a long incident all happen in the gaps, when nothing is running and
therefore nothing notices.

Two of those gaps are closed here.

**A plan going stale at the gate.** Notes that arrive while an incident is
parked awaiting approval are queued, and the queue is only drained when a run
finishes — which cannot happen until somebody approves. So an unattended gate
does not merely delay containment, it stops the investigation absorbing anything
at all, for as long as the gate stays shut. Past `STALE_GATE_SECONDS`, with
notes actually waiting, the plan is withdrawn and rebuilt on everything now
known. Nobody is overruled: the plan being withdrawn is one no human ever ruled
on, and the human gets a better one.

**Going quiet.** In winger and responder modes the bot owes the room a periodic
catch-up. A timer per incident would not survive a restart, so this asks the
opposite question on a fixed tick — who is overdue — which needs no memory
beyond a column.

The loop is deliberately independent of the Slack poller. Withdrawing a stale
plan is a correctness property of the investigation, not a chat feature, and it
has to keep working in a deployment where nobody has turned polling on.
"""

from __future__ import annotations

import asyncio
import contextlib

from app.config import get_settings
from app.observability import UPKEEP_ACTIONS, get_logger
from app.services import incidents

log = get_logger(__name__)

# One sweep must never turn into a stampede: a backlog of fifty stale gates
# re-planning at once would swamp the run semaphore and the rate limit alike.
_MAX_WITHDRAWALS = 3
_MAX_DIGESTS = 10


async def replan_stale_gates() -> int:
    """Withdraw containment plans that new information has overtaken."""
    settings = get_settings()
    window = settings.stale_gate_seconds
    if window <= 0:
        return 0

    stale = await incidents.stale_gates(window, limit=_MAX_WITHDRAWALS * 2)
    withdrawn = 0
    for record in stale[:_MAX_WITHDRAWALS]:
        queued = len(record.get("pending_notes") or [])
        reason = (
            f"{queued} update(s) arrived while this waited for approval; "
            "re-planning on the current picture"
        )
        from app.services import runner

        try:
            outcome = await runner.withdraw_plan(record["id"], reason=reason)
        except Exception as exc:  # noqa: BLE001 — one bad incident must not stop the rest
            log.error("upkeep.withdraw_failed", incident_id=record["id"], error=str(exc))
            continue
        if outcome != "withdrawn":
            continue
        withdrawn += 1
        UPKEEP_ACTIONS.labels(action="withdraw_stale_plan").inc()
        log.info("upkeep.plan_withdrawn", incident_id=record["id"], queued_notes=queued)
        await _say(
            record,
            ":arrows_counterclockwise: *Plan withdrawn* — it had been waiting "
            f"{max(1, window // 60)}+ min while {queued} update(s) came in. "
            "Nothing was executed. Re-planning on what we know now; "
            "you'll get a fresh set to approve.",
        )
    if len(stale) > _MAX_WITHDRAWALS:
        log.info("upkeep.withdrawals_capped", seen=len(stale), handled=_MAX_WITHDRAWALS)
    return withdrawn


async def post_digests() -> int:
    """Publish catch-ups for incidents whose cadence is due."""
    settings = get_settings()
    if not settings.slack_enabled:
        return 0

    due = await incidents.due_for_digest(settings.ir_digest_seconds, limit=_MAX_DIGESTS)
    posted = 0
    from app.slack import digest

    for record in due:
        try:
            # A full record — `due_for_digest` lists without the report, and the
            # digest reads the alert and findings behind it.
            full = await incidents.get_incident(record["id"]) or record
            if not await digest.post(full):
                # Nothing to say and nothing stuck. Leave the clock untouched so
                # the next tick reconsiders rather than waiting a whole cadence.
                continue
            await incidents.mark_digested(record["id"])
        except Exception as exc:  # noqa: BLE001
            log.error("upkeep.digest_failed", incident_id=record["id"], error=str(exc))
            continue
        posted += 1
        UPKEEP_ACTIONS.labels(action="digest").inc()
    return posted


async def _say(record: dict[str, object], text: str) -> None:
    """Tell the incident's channel something. Never raises."""
    if not get_settings().slack_enabled:
        return
    channel = str(record.get("slack_channel") or "")
    if not channel:
        return
    try:
        from app.slack import notifier

        await notifier.post(
            channel,
            text=text,
            blocks_payload=[{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
            thread_ts=str(record.get("slack_thread_ts") or ""),
        )
    except Exception as exc:  # noqa: BLE001
        log.debug("upkeep.say_failed", incident_id=record.get("id"), error=str(exc))


async def sweep() -> dict[str, int]:
    """One caretaker pass. Each duty is isolated — neither can suppress the other."""
    result = {"withdrawn": 0, "digests": 0}
    for key, duty in (("withdrawn", replan_stale_gates), ("digests", post_digests)):
        try:
            result[key] = await duty()
        except Exception as exc:  # noqa: BLE001 — the caretaker outlives its duties
            log.error("upkeep.duty_failed", duty=key, error=str(exc))
    return result


# ── Lifecycle ────────────────────────────────────────────────────────────────

_task: asyncio.Task | None = None


async def _loop() -> None:
    settings = get_settings()
    interval = max(30, settings.upkeep_interval_seconds)
    log.info(
        "upkeep.started",
        interval=interval,
        stale_gate_seconds=settings.stale_gate_seconds,
        digest_seconds=settings.ir_digest_seconds,
    )
    while True:
        await asyncio.sleep(interval)
        try:
            result = await sweep()
            if any(result.values()):
                log.info("upkeep.swept", **result)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("upkeep.cycle_failed", error=str(exc))


def start() -> None:
    """Begin the caretaker loop. Idempotent."""
    global _task
    if not get_settings().upkeep_enabled:
        return
    if _task is not None and not _task.done():
        return
    _task = asyncio.create_task(_loop())


async def stop() -> None:
    global _task
    if _task is None:
        return
    _task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await _task
    _task = None
    log.info("upkeep.stopped")
