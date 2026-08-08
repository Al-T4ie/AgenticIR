"""Incident index.

LangGraph's checkpointer already stores full graph state; this table is the
queryable projection on top of it — what the dashboard lists, what Slack maps
threads to, and what survives as the audit record.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Index, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    thread_id: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(32), default="api")
    status: Mapped[str] = mapped_column(String(32), default="running", index=True)

    title: Mapped[str] = mapped_column(String(512), default="")
    severity: Mapped[str] = mapped_column(String(16), default="informational", index=True)
    verdict: Mapped[str] = mapped_column(String(32), default="inconclusive")
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    report: Mapped[str] = mapped_column(Text, default="")

    alert: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    findings: Mapped[list[Any]] = mapped_column(JSON, default=list)
    timeline: Mapped[list[Any]] = mapped_column(JSON, default=list)
    containment_actions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # What was actually run, as opposed to what was proposed. This is the
    # audit answer to "did anything touch production?" and must survive on the
    # record, not only inside graph state.
    executed_actions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    errors: Mapped[list[Any]] = mapped_column(JSON, default=list)

    slack_channel: Mapped[str] = mapped_column(String(64), default="")
    slack_thread_ts: Mapped[str] = mapped_column(String(64), default="")

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_incidents_created_at_desc", created_at.desc()),
        Index("ix_incidents_status_severity", "status", "severity"),
    )

    def as_dict(self, *, include_report: bool = True) -> dict[str, Any]:
        data = {
            "id": self.id,
            "thread_id": self.thread_id,
            "source": self.source,
            "status": self.status,
            "title": self.title,
            "severity": self.severity,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "summary": self.summary,
            "findings": self.findings or [],
            "timeline": self.timeline or [],
            "containment_actions": self.containment_actions or [],
            "executed_actions": self.executed_actions or [],
            "errors": self.errors or [],
            "slack_channel": self.slack_channel,
            "slack_thread_ts": self.slack_thread_ts,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_report:
            data["report"] = self.report
        return data
