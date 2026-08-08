"""Incident index reads/writes — the queryable projection of graph state."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select

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
        row.errors = state.get("errors", row.errors) or []
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


async def attach_slack_thread(incident_id: str, channel: str, thread_ts: str) -> None:
    async with session_scope() as session:
        row = await session.get(Incident, incident_id)
        if row is not None:
            row.slack_channel = channel
            row.slack_thread_ts = thread_ts
