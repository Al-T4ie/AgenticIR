"""Incident index.

LangGraph's checkpointer already stores full graph state; this table is the
queryable projection on top of it — what the dashboard lists, what Slack maps
threads to, and what survives as the audit record.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, Index, Integer, String, Text, func
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
    # What the investigation needs from a human and has not been told yet.
    open_questions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # Information that arrived while the incident could not absorb it — during a
    # run, or under a pending approval. Applied when it next becomes idle, so
    # intelligence is never rejected for arriving at an inconvenient moment.
    pending_notes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    # One entry per model call and per tool call: who spent it, on what, and
    # what it touched. The Prometheus counters cannot answer this — they carry
    # no incident label, and adding one would blow up cardinality.
    usage: Mapped[list[Any]] = mapped_column(JSON, default=list)

    slack_channel: Mapped[str] = mapped_column(String(64), default="")
    slack_thread_ts: Mapped[str] = mapped_column(String(64), default="")

    # How much rope the bot has here: spectator, winger or responder. Per
    # incident rather than global, because the posture that suits a contained
    # phishing report is not the one that suits a live exfiltration.
    mode: Mapped[str] = mapped_column(String(24), default="spectator")
    mode_set_by: Mapped[str] = mapped_column(String(64), default="")
    # When the incident's own channel was opened. The mode ladder unlocks a few
    # minutes after this, so nobody hands over control before reading anything.
    channel_opened_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Last catch-up digest, so the ten-minute cadence survives a restart.
    last_digest_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, server_default=func.now()
    )

    __table_args__ = (
        Index("ix_incidents_created_at_desc", created_at.desc()),
        Index("ix_incidents_status_severity", "status", "severity"),
        Index("ix_incidents_slack_thread", "slack_channel", "slack_thread_ts"),
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
            "open_questions": self.open_questions or [],
            "pending_notes": self.pending_notes or [],
            "slack_channel": self.slack_channel,
            "slack_thread_ts": self.slack_thread_ts,
            "mode": self.mode or "spectator",
            "mode_set_by": self.mode_set_by,
            "channel_opened_at": (
                self.channel_opened_at.isoformat() if self.channel_opened_at else None
            ),
            "last_digest_at": self.last_digest_at.isoformat() if self.last_digest_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_report:
            data["report"] = self.report
            # The originating alert is stored but was never serialised, so no
            # consumer could see what the investigation was actually handed —
            # which also made the detection lag uncomputable. Detail views only:
            # a raw SIEM payload per row would bloat every list response.
            data["alert"] = self.alert or {}
            data["usage"] = self.usage or []
        return data


# ── Threat intelligence corpus ───────────────────────────────────────────────
# Schema adapted from the Cognitive CTI project (Al-T4ie/muraqib-cognitiveCTI),
# which built it for a standalone strategic-intelligence pipeline. The shape is
# kept deliberately close to the original so the two can share ingestion later,
# minus the tables that only make sense there (Telegram channel tracking) and
# the ones that need a corpus we do not have yet (correlations, trend
# snapshots).
#
# The point of holding this locally rather than querying vendors per-incident:
# an investigation asks "have we seen this before", and that question can only
# be answered by something that has been watching.


class CTIReport(Base):
    """One piece of published intelligence — an advisory, a feed batch, a post."""

    __tablename__ = "cti_reports"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Stable identity from the source, so re-ingesting a feed updates rather
    # than duplicates. A corpus that double-counts makes "seen in 9 reports"
    # a measure of how often the poller ran.
    external_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)

    title: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    summary: Mapped[str] = mapped_column(Text, default="")

    report_type: Mapped[str] = mapped_column(String(48), default="threat-report")
    source: Mapped[str] = mapped_column(String(96), default="", index=True)
    source_url: Mapped[str] = mapped_column(Text, default="")
    # Which intelligence layer this came from: 1 vendor, 2 research, 3 sector,
    # 4 IOC feed, 5 threat-actor channel. Trust decreases as the number rises,
    # and a verdict that rests only on layer 5 should say so.
    layer: Mapped[int] = mapped_column(Integer, default=4)

    confidence: Mapped[int] = mapped_column(Integer, default=0)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    tlp: Mapped[str] = mapped_column(String(24), default="TLP:CLEAR")

    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ingested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
    raw: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    __table_args__ = (Index("ix_cti_reports_published", published_at.desc()),)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "external_id": self.external_id,
            "title": self.title,
            "summary": self.summary or self.description,
            "report_type": self.report_type,
            "source": self.source,
            "source_url": self.source_url,
            "layer": self.layer,
            "confidence": self.confidence,
            "severity": self.severity,
            "tlp": self.tlp,
            "published_at": self.published_at.isoformat() if self.published_at else None,
        }


class CTIEntity(Base):
    """A thing intelligence is about: an indicator, actor, malware family, CVE."""

    __tablename__ = "cti_entities"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # indicator | threat-actor | malware | vulnerability | attack-pattern | tool
    # | campaign | sector | region
    entity_type: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str] = mapped_column(String(512))
    # Lowercased, whitespace-stripped. Lookup happens on this and never on
    # `name`: an analyst pastes `CDN-Update-Service.TOP` and the feed stored
    # `cdn-update-service.top`, and a case-sensitive miss reads exactly like
    # "we have never seen this" — the most dangerous wrong answer here.
    normalised: Mapped[str] = mapped_column(String(512), index=True)
    # For indicators: ipv4 | domain | url | sha256 | md5 | email. Empty otherwise.
    kind: Mapped[str] = mapped_column(String(24), default="")
    description: Mapped[str] = mapped_column(Text, default="")

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )

    __table_args__ = (Index("ix_cti_entities_type_norm", "entity_type", "normalised", unique=True),)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "entity_type": self.entity_type,
            "name": self.name,
            "kind": self.kind,
            "description": self.description,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


class CTIReportEntity(Base):
    """Which entities appear in which reports — the join that makes it a graph."""

    __tablename__ = "cti_report_entities"

    report_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    entity_id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    relationship: Mapped[str] = mapped_column(String(32), primary_key=True, default="mentions")
    confidence: Mapped[int] = mapped_column(Integer, default=50)
    # feed | ai | manual — an AI-extracted link and a feed-asserted one carry
    # very different weight, and collapsing them hides which is which.
    extracted_by: Mapped[str] = mapped_column(String(16), default="feed")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )


class CTITag(Base):
    """Free-form topic labels for trend and sector questions."""

    __tablename__ = "cti_report_tags"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    report_id: Mapped[str] = mapped_column(String(64), index=True)
    tag: Mapped[str] = mapped_column(String(128), index=True)
    category: Mapped[str] = mapped_column(String(32), default="")
    weight: Mapped[float] = mapped_column(Float, default=1.0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )


class CTIFeedState(Base):
    """How far each feed has been read, and whether it is healthy.

    A feed that has been failing for a week is indistinguishable from a quiet
    one unless the failure is recorded — and "no intelligence" reads as "nothing
    to worry about", which is the wrong way for this to fail.
    """

    __tablename__ = "cti_feed_state"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    cursor: Mapped[str] = mapped_column(String(255), default="")
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_ok_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    consecutive_failures: Mapped[int] = mapped_column(Integer, default=0)
    items_ingested: Mapped[int] = mapped_column(Integer, default=0)


class SlackCursor(Base):
    """How far the channel poller has read in each channel."""

    __tablename__ = "slack_cursors"

    channel: Mapped[str] = mapped_column(String(64), primary_key=True)
    # Slack message timestamps are strings ("1754671234.001900") and sort
    # lexicographically only by accident of fixed width — compare them as floats.
    last_ts: Mapped[str] = mapped_column(String(32), default="")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, server_default=func.now()
    )


class SlackSeenMessage(Base):
    """One row per message the bot has taken responsibility for.

    This is a *claim*, not a log: the poller inserts with ON CONFLICT DO NOTHING
    and only acts on rows it actually created. That makes the sweep idempotent
    across restarts, safe to run in more than one worker, and non-overlapping
    with the Events API path, which claims the same way before handling a
    mention.
    """

    __tablename__ = "slack_seen_messages"

    channel: Mapped[str] = mapped_column(String(64), primary_key=True)
    ts: Mapped[str] = mapped_column(String(32), primary_key=True)
    # claimed → being worked on · handled → finished · deferred → retry next sweep
    status: Mapped[str] = mapped_column(String(16), default="claimed", index=True)
    disposition: Mapped[str] = mapped_column(String(32), default="")
    incident_id: Mapped[str] = mapped_column(String(64), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, server_default=func.now()
    )
