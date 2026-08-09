"""Incident index reads/writes — the queryable projection of graph state."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select

from app.db.models import Incident
from app.db.session import session_scope
from app.observability import get_logger

log = get_logger(__name__)


def new_incident_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%d")
    return f"INC-{stamp}-{uuid.uuid4().hex[:8]}"


def derive_title(alert: dict[str, Any], question: str = "") -> str:
    for key in ("title", "name", "rule_name", "signature", "message", "description"):
        value = alert.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:200]
    if question:
        return question.strip()[:200]
    return "Untitled incident"


async def create_incident(
    *,
    incident_id: str,
    thread_id: str,
    source: str,
    alert: dict[str, Any],
    question: str = "",
    slack_channel: str = "",
    slack_thread_ts: str = "",
) -> dict[str, Any]:
    async with session_scope() as session:
        row = Incident(
            id=incident_id,
            thread_id=thread_id,
            source=source,
            status="running",
            title=derive_title(alert, question),
            alert=alert,
            slack_channel=slack_channel,
            slack_thread_ts=slack_thread_ts,
        )
        session.add(row)
        await session.flush()
        return row.as_dict()


async def save_state(incident_id: str, state: dict[str, Any], status: str | None = None) -> None:
    """Project graph state onto the index row. Called after every run/resume."""
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is None:
            log.warning("incidents.save_state_missing_row", incident_id=incident_id)
            return

        row.status = status or str(state.get("status", row.status))
        row.severity = str(state.get("severity", row.severity))
        row.verdict = str(state.get("verdict", row.verdict))
        row.confidence = float(state.get("confidence", row.confidence) or 0.0)
        row.summary = str(state.get("summary", row.summary) or "")
        row.report = str(state.get("report", row.report) or "")
        row.findings = state.get("findings", row.findings) or []
        row.timeline = state.get("timeline", row.timeline) or []
        row.containment_actions = state.get("containment_actions", row.containment_actions) or []
        row.executed_actions = state.get("executed_actions", row.executed_actions) or []
        row.errors = state.get("errors", row.errors) or []
        row.open_questions = state.get("open_questions", row.open_questions) or []
        row.updated_at = datetime.now(UTC)


async def set_status(incident_id: str, status: str) -> None:
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is not None:
            row.status = status
            row.updated_at = datetime.now(UTC)


async def get_incident(incident_id: str) -> dict[str, Any] | None:
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        return row.as_dict() if row else None


async def get_by_slack_thread(channel: str, thread_ts: str) -> dict[str, Any] | None:
    async with session_scope() as session:
        stmt = (
            select(Incident)
            .where(Incident.slack_channel == channel, Incident.slack_thread_ts == thread_ts)
            .order_by(Incident.created_at.desc())
            .limit(1)
        )
        row = (await session.execute(stmt)).scalar_one_or_none()
        return row.as_dict() if row else None


async def list_incidents(
    *, limit: int = 50, offset: int = 0, status: str | None = None, severity: str | None = None
) -> list[dict[str, Any]]:
    async with session_scope() as session:
        stmt = select(Incident).order_by(Incident.created_at.desc()).limit(limit).offset(offset)
        if status:
            stmt = stmt.where(Incident.status == status)
        if severity:
            stmt = stmt.where(Incident.severity == severity)
        rows = (await session.execute(stmt)).scalars().all()
        return [r.as_dict(include_report=False) for r in rows]


async def queue_note(incident_id: str, note: str, reported_by: str = "") -> int:
    """Park information the incident cannot absorb yet. Returns the queue depth."""
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is None:
            return 0
        queued = list(row.pending_notes or [])
        queued.append({"at": datetime.now(UTC).isoformat(), "by": reported_by, "note": note})
        row.pending_notes = queued
        row.updated_at = datetime.now(UTC)
        return len(queued)


async def drain_notes(incident_id: str) -> list[dict[str, Any]]:
    """Take everything queued, clearing it in the same transaction.

    Read-then-clear atomically: a note handed out twice would re-run an
    investigation for information it has already folded in.
    """
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is None or not row.pending_notes:
            return []
        queued = list(row.pending_notes)
        row.pending_notes = []
        return queued


async def attach_slack_thread(incident_id: str, channel: str, thread_ts: str) -> None:
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is not None:
            row.slack_channel = channel
            row.slack_thread_ts = thread_ts


async def append_usage(incident_id: str, entries: list[dict[str, Any]]) -> None:
    """Append model and tool spend. Additive — a revision adds to the bill."""
    if not entries:
        return
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is None:
            return
        row.usage = [*(row.usage or []), *entries]
        row.updated_at = datetime.now(UTC)


async def get_by_slack_channel(channel: str) -> dict[str, Any] | None:
    """The incident that owns this channel, if it is a war room.

    Only matches rooms — an incident narrating into the shared channel has a
    thread ts, and treating every mention in that channel as belonging to it
    would hijack unrelated conversation.
    """
    if not channel:
        return None
    async with session_scope() as session:
        stmt = (
            select(Incident)
            .where(Incident.slack_channel == channel, Incident.slack_thread_ts == "")
            .order_by(Incident.created_at.desc())
            .limit(1)
        )
        row = (await session.execute(stmt)).scalar_one_or_none()
        return row.as_dict() if row else None


async def append_timeline(incident_id: str, entry: dict[str, Any]) -> None:
    """Add one event to the record's timeline, stamping it if the caller did not.

    Used for things that happen outside the graph — a mode change, a room being
    opened — which still belong on the incident's history.
    """
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is None:
            return
        item = {"at": entry.get("at") or datetime.now(UTC).isoformat(), **entry}
        row.timeline = [*(row.timeline or []), item]
        row.updated_at = datetime.now(UTC)


async def attach_war_room(incident_id: str, channel: str) -> None:
    """Adopt a dedicated channel. Clears the thread — the room replaces it.

    Stamping `channel_opened_at` here rather than at creation keeps the mode
    unlock tied to the moment the room became the incident's home, which is the
    moment a responder could first have read anything in it.
    """
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is not None:
            row.slack_channel = channel
            row.slack_thread_ts = ""
            row.channel_opened_at = datetime.now(UTC)
            row.updated_at = datetime.now(UTC)


async def set_mode(incident_id: str, mode: str, *, by: str = "") -> None:
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is not None:
            row.mode = mode
            row.mode_set_by = by
            row.updated_at = datetime.now(UTC)


async def mark_digested(incident_id: str) -> None:
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is not None:
            row.last_digest_at = datetime.now(UTC)


async def due_for_digest(interval_seconds: int, limit: int = 25) -> list[dict[str, Any]]:
    """Open incidents whose catch-up is due, in a mode that has catch-ups.

    Driven off the poller tick rather than a timer per incident: one sweep that
    asks "who is overdue" survives a restart, and a per-incident timer does not.
    """
    from app.services import modes as modes_mod

    cadence = [k for k, m in modes_mod.MODES.items() if m.digest_seconds > 0]
    if not cadence:
        return []
    cutoff = datetime.now(UTC) - timedelta(seconds=max(interval_seconds, 60))
    async with session_scope() as session:
        stmt = (
            select(Incident)
            .where(
                Incident.mode.in_(cadence),
                Incident.status.in_(["running", "awaiting_approval"]),
                Incident.slack_channel != "",
                or_(Incident.last_digest_at.is_(None), Incident.last_digest_at < cutoff),
            )
            .order_by(Incident.updated_at.desc())
            .limit(limit)
        )
        rows = (await session.execute(stmt)).scalars().all()
        return [r.as_dict(include_report=False) for r in rows]
