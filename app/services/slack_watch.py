"""Bookkeeping for the Slack channel poller.

The poller and the Events API both react to channel messages, and the poller
itself may run in more than one worker. Rather than coordinating them with a
lock, every message is *claimed*: an insert that either succeeds (this process
owns the message) or hits the primary key and does nothing (someone else already
has it). Claims are cheap, crash-safe, and make the sweep idempotent.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.db.models import SlackCursor, SlackSeenMessage
from app.db.session import session_scope
from app.observability import get_logger

log = get_logger(__name__)


async def claim(channel: str, ts: str, *, disposition: str = "") -> bool:
    """Take ownership of a message. False means someone else already had it."""
    async with session_scope() as session:
        stmt = (
            pg_insert(SlackSeenMessage)
            .values(channel=channel, ts=ts, status="claimed", disposition=disposition)
            .on_conflict_do_nothing(index_elements=["channel", "ts"])
            .returning(SlackSeenMessage.ts)
        )
        return (await session.execute(stmt)).scalar_one_or_none() is not None


async def release(channel: str, ts: str, *, disposition: str, incident_id: str = "") -> None:
    """Mark a claimed message finished."""
    async with session_scope() as session:
        row = await session.get(SlackSeenMessage, (channel, ts))
        if row is None:
            return
        row.status = "handled"
        row.disposition = disposition
        row.incident_id = incident_id or row.incident_id


async def defer(channel: str, ts: str, *, max_attempts: int = 5) -> bool:
    """Hand a message back for the next sweep.

    Used when an incident is mid-run and cannot absorb new information yet.
    Returns False once the retry budget is spent, so a message that can never be
    applied stops coming round again.
    """
    async with session_scope() as session:
        row = await session.get(SlackSeenMessage, (channel, ts))
        if row is None:
            return False
        row.attempts += 1
        if row.attempts >= max_attempts:
            row.status = "handled"
            row.disposition = "abandoned"
            return False
        row.status = "deferred"
        return True


async def deferred(channel: str, limit: int = 20) -> list[str]:
    """Timestamps previously deferred in this channel, oldest first."""
    async with session_scope() as session:
        stmt = (
            select(SlackSeenMessage.ts)
            .where(SlackSeenMessage.channel == channel, SlackSeenMessage.status == "deferred")
            .order_by(SlackSeenMessage.ts)
            .limit(limit)
        )
        return [ts for (ts,) in (await session.execute(stmt)).all()]


async def reclaim(channel: str, ts: str) -> bool:
    """Re-take a deferred message. False if it is no longer deferred."""
    async with session_scope() as session:
        row = await session.get(SlackSeenMessage, (channel, ts))
        if row is None or row.status != "deferred":
            return False
        row.status = "claimed"
        return True


async def requeue_stale(older_than_minutes: int = 15, max_attempts: int = 5) -> int:
    """Rescue claims orphaned by a crash.

    A claim taken just before the process died stays `claimed` for ever and the
    message is never acted on — the one way this scheme can silently drop work.
    Anything held that long is assumed abandoned and offered round again.
    """
    cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
    async with session_scope() as session:
        stmt = select(SlackSeenMessage).where(
            SlackSeenMessage.status == "claimed",
            SlackSeenMessage.created_at < cutoff,
            SlackSeenMessage.attempts < max_attempts,
        )
        rows = (await session.execute(stmt)).scalars().all()
        for row in rows:
            row.status = "deferred"
            row.attempts += 1
        if rows:
            log.info("slack_watch.requeued_stale", count=len(rows))
        return len(rows)


async def get_cursor(channel: str) -> str:
    async with session_scope() as session:
        row = await session.get(SlackCursor, channel)
        return row.last_ts if row else ""


async def set_cursor(channel: str, last_ts: str) -> None:
    """Advance the read position, never rewind it."""
    async with session_scope() as session:
        row = await session.get(SlackCursor, channel)
        if row is None:
            session.add(SlackCursor(channel=channel, last_ts=last_ts))
            return
        if _as_float(last_ts) > _as_float(row.last_ts):
            row.last_ts = last_ts
            row.updated_at = datetime.now(UTC)


async def prune(older_than_days: int = 30) -> int:
    """Drop old claims. The incident record is the audit trail, not this table."""
    cutoff = datetime.now(UTC) - timedelta(days=older_than_days)
    async with session_scope() as session:
        result = await session.execute(
            delete(SlackSeenMessage).where(
                SlackSeenMessage.created_at < cutoff, SlackSeenMessage.status == "handled"
            )
        )
        return int(result.rowcount or 0)


def _as_float(ts: str) -> float:
    try:
        return float(ts)
    except (TypeError, ValueError):
        return 0.0
