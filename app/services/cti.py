"""The threat intelligence corpus: what goes in, and what comes back out.

Until now `enrich_ioc` answered from a dictionary someone typed by hand. That is
fine for a demo and indefensible in an investigation: every verdict the critic
reached, every severity, every containment plan, rested on a lookup table that
knew about four indicators. This module is the replacement — a local corpus,
populated from feeds, queried in SQL while an incident is live.

Two rules govern everything here, and both come from the Cognitive CTI project
this schema is adapted from:

**An indicator we did not check returns `unknown`, never `clean`.** A fabricated
clean verdict is how a real detection gets suppressed, and it is worse than no
answer at all because it carries the authority of a lookup. Every response
distinguishes "absent from the corpus" from "checked and benign".

**Provenance travels with the answer.** "Malicious" from a vendor advisory and
"malicious" from a Telegram channel are not the same claim. Layer and source
come back with every hit so the agent can weigh them, and so a report can say
where the assessment came from.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select

from app.db.models import CTIEntity, CTIFeedState, CTIReport, CTIReportEntity, CTITag
from app.db.session import session_scope
from app.observability import get_logger

log = get_logger(__name__)

# Layer 1 is a government advisory; layer 5 is a criminal's Telegram channel.
# Both are intelligence, and treating them alike is how a rumour becomes a
# containment action.
LAYERS = {
    1: "vendor/government advisory",
    2: "independent research",
    3: "sector feed",
    4: "IOC feed",
    5: "threat-actor channel",
}


def _id() -> str:
    return uuid.uuid4().hex


def normalise(value: str) -> str:
    """The lookup key. Indicators are matched on this, never on raw text."""
    return " ".join(str(value or "").strip().lower().split())


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


# ── Writing ──────────────────────────────────────────────────────────────────


async def _report(
    session: Any, *, external_id: str, title: str, source: str, layer: int, **kw
) -> str:
    """Store a report, or refresh it if the source has published it before."""
    stmt = select(CTIReport).where(CTIReport.external_id == external_id).limit(1)
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = CTIReport(id=_id(), external_id=external_id[:255])
        session.add(row)
    row.title = title[:2000]
    row.source = source
    row.layer = layer
    row.description = kw.get("description", "")
    row.summary = kw.get("summary", "")
    row.report_type = kw.get("report_type", "threat-report")
    row.source_url = kw.get("source_url", "")
    row.severity = kw.get("severity", "info")
    row.confidence = int(kw.get("confidence", 0))
    row.tlp = kw.get("tlp", "TLP:CLEAR")
    row.published_at = kw.get("published_at")
    row.raw = kw.get("raw") or {}
    await session.flush()
    return row.id


async def _entity(
    session: Any,
    *,
    entity_type: str,
    name: str,
    kind: str = "",
    description: str = "",
    seen_at: datetime | None = None,
) -> str:
    """Store an entity, widening its first/last-seen window if it already exists.

    The window is the whole point of keeping a corpus. "This domain was
    registered eleven days ago and we first saw it yesterday" is an argument;
    "this domain is malicious" is an assertion.
    """
    key = normalise(name)
    stamp = seen_at or datetime.now(UTC)
    stmt = (
        select(CTIEntity)
        .where(CTIEntity.entity_type == entity_type, CTIEntity.normalised == key)
        .limit(1)
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = CTIEntity(
            id=_id(),
            entity_type=entity_type,
            name=name[:512],
            normalised=key[:512],
            kind=kind,
            description=description,
            first_seen=stamp,
            last_seen=stamp,
        )
        session.add(row)
        await session.flush()
        return row.id

    first, last = _aware(row.first_seen), _aware(row.last_seen)
    if first is None or stamp < first:
        row.first_seen = stamp
    if last is None or stamp > last:
        row.last_seen = stamp
    if description and not row.description:
        row.description = description
    if kind and not row.kind:
        row.kind = kind
    return row.id


async def _link(
    session: Any,
    report_id: str,
    entity_id: str,
    *,
    relationship: str = "mentions",
    confidence: int = 50,
    extracted_by: str = "feed",
) -> None:
    existing = await session.get(CTIReportEntity, (report_id, entity_id, relationship))
    if existing is not None:
        existing.confidence = max(existing.confidence, confidence)
        return
    session.add(
        CTIReportEntity(
            report_id=report_id,
            entity_id=entity_id,
            relationship=relationship,
            confidence=confidence,
            extracted_by=extracted_by,
        )
    )


# Public single-item wrappers. The batch path below is what feeds use — a
# thousand indicators at one transaction each is a feed that never finishes.
async def upsert_report(**kw: Any) -> str:
    async with session_scope() as session:
        return await _report(session, **kw)


async def upsert_entity(**kw: Any) -> str:
    async with session_scope() as session:
        return await _entity(session, **kw)


async def link(report_id: str, entity_id: str, **kw: Any) -> None:
    async with session_scope() as session:
        await _link(session, report_id, entity_id, **kw)


async def tag(report_id: str, tags: list[str], *, category: str = "") -> None:
    if not tags:
        return
    async with session_scope() as session:
        for value in tags:
            cleaned = str(value).strip()[:128]
            if cleaned:
                session.add(CTITag(id=_id(), report_id=report_id, tag=cleaned, category=category))


async def ingest_batch(
    *,
    external_id: str,
    title: str,
    source: str,
    layer: int,
    items: list[dict[str, Any]],
    published_at: datetime | None = None,
    severity: str = "info",
    source_url: str = "",
) -> int:
    """Write one feed run — the report and everything it asserted — atomically.

    All of it in a single transaction, so a feed that dies halfway through
    leaves no half-ingested batch claiming to be complete. Returns the number of
    entities written.

    Each item is `{"entity_type", "name", "kind", "description", "tags",
    "relationship", "confidence"}`.
    """
    if not items:
        return 0
    written = 0
    async with session_scope() as session:
        report_id = await _report(
            session,
            external_id=external_id,
            title=title,
            source=source,
            layer=layer,
            severity=severity,
            source_url=source_url,
            published_at=published_at,
            report_type="ioc-feed" if layer >= 4 else "threat-report",
        )
        seen: set[tuple[str, str]] = set()
        for item in items:
            entity_type = str(item.get("entity_type") or "indicator")
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            key = (entity_type, normalise(name))
            entity_id = await _entity(
                session,
                entity_type=entity_type,
                name=name,
                kind=str(item.get("kind") or ""),
                description=str(item.get("description") or ""),
                seen_at=item.get("seen_at") or published_at,
            )
            await _link(
                session,
                report_id,
                entity_id,
                relationship=str(item.get("relationship") or "mentions"),
                confidence=int(item.get("confidence") or 50),
            )
            for value in item.get("tags") or []:
                cleaned = str(value).strip()[:128]
                if cleaned:
                    session.add(CTITag(id=_id(), report_id=report_id, tag=cleaned, category="feed"))
            if key not in seen:
                seen.add(key)
                written += 1
    return written


# ── Reading ──────────────────────────────────────────────────────────────────


async def _reports_for(entity_id: str, limit: int = 12) -> list[dict[str, Any]]:
    async with session_scope() as session:
        stmt = (
            select(CTIReport)
            .join(CTIReportEntity, CTIReportEntity.report_id == CTIReport.id)
            .where(CTIReportEntity.entity_id == entity_id)
            .order_by(CTIReport.published_at.desc().nullslast())
            .limit(limit)
        )
        return [r.as_dict() for r in (await session.execute(stmt)).scalars().all()]


async def _co_occurring(
    entity_id: str, types: tuple[str, ...], limit: int = 10
) -> list[dict[str, Any]]:
    """Entities that show up in the same reports — the associations worth having.

    This is what turns a corpus into intelligence: the indicator itself says
    little, but "every report containing it also names ShinyHunters" is the
    finding an analyst acts on.
    """
    async with session_scope() as session:
        mine = select(CTIReportEntity.report_id).where(CTIReportEntity.entity_id == entity_id)
        stmt = (
            select(CTIEntity, func.count(CTIReportEntity.report_id).label("shared"))
            .join(CTIReportEntity, CTIReportEntity.entity_id == CTIEntity.id)
            .where(
                CTIReportEntity.report_id.in_(mine),
                CTIEntity.id != entity_id,
                CTIEntity.entity_type.in_(types),
            )
            .group_by(CTIEntity.id)
            .order_by(func.count(CTIReportEntity.report_id).desc())
            .limit(limit)
        )
        return [
            {**entity.as_dict(), "shared_reports": shared}
            for entity, shared in (await session.execute(stmt)).all()
        ]


async def corpus_size() -> dict[str, Any]:
    """How much the corpus actually knows. An empty one must say so out loud."""
    async with session_scope() as session:
        reports = await session.scalar(select(func.count()).select_from(CTIReport))
        entities = await session.scalar(select(func.count()).select_from(CTIEntity))
        newest = await session.scalar(select(func.max(CTIReport.ingested_at)))
    return {
        "reports": int(reports or 0),
        "entities": int(entities or 0),
        "last_ingest": newest.isoformat() if newest else "",
    }


# What an analyst can paste into a lookup. A CVE lives under `vulnerability`
# rather than `indicator`, and searching only the latter made the whole CISA KEV
# catalogue invisible to the tool that exists to query it — 1,665 entities in
# the corpus and `check_indicator("CVE-2021-44228")` answering "never seen".
_LOOKUPABLE = ("indicator", "vulnerability")


async def lookup_indicator(value: str) -> dict[str, Any]:
    """What the corpus knows about one IP, domain, URL, hash or CVE.

    `known: False` means absent from the corpus — which is *not* a clean
    verdict, and the returned payload says so in words rather than leaving the
    model to infer it.
    """
    key = normalise(value)
    if not key:
        return {"known": False, "indicator": value, "reason": "empty indicator"}

    async with session_scope() as session:
        stmt = (
            select(CTIEntity)
            .where(CTIEntity.entity_type.in_(_LOOKUPABLE), CTIEntity.normalised == key)
            .limit(1)
        )
        entity = (await session.execute(stmt)).scalar_one_or_none()
        found = entity.as_dict() if entity else None
        entity_id = entity.id if entity else ""

    size = await corpus_size()
    if not found:
        return {
            "known": False,
            "indicator": value,
            "verdict": "unknown",
            "note": (
                "Not present in the local threat intelligence corpus. This is NOT a "
                "clean verdict — it means no ingested source has reported this "
                "indicator. Treat as unassessed."
            ),
            "corpus": size,
        }

    reports = await _reports_for(entity_id)
    associations = await _co_occurring(
        entity_id, ("threat-actor", "malware", "campaign", "attack-pattern")
    )
    layers = sorted({r["layer"] for r in reports})
    return {
        "known": True,
        "indicator": value,
        "entity_type": found["entity_type"],
        # A CVE on the KEV catalogue is not "malicious infrastructure" — it is a
        # vulnerability with confirmed exploitation, and calling both the same
        # thing loses the distinction an analyst is actually acting on.
        "verdict": (
            "known-exploited" if found["entity_type"] == "vulnerability" else "reported-malicious"
        ),
        "kind": found["kind"],
        "first_seen": found["first_seen"],
        "last_seen": found["last_seen"],
        "description": found["description"],
        "report_count": len(reports),
        "sources": sorted({r["source"] for r in reports}),
        # The weakest layer present is what a cautious reader needs; a hit that
        # exists only at layer 5 is a rumour with a citation.
        "best_layer": min(layers) if layers else None,
        "best_layer_meaning": LAYERS.get(min(layers)) if layers else "",
        "reports": reports[:6],
        "associated": associations,
        "corpus": size,
    }


async def actor_profile(name: str) -> dict[str, Any]:
    """Everything the corpus holds on a named threat actor."""
    key = normalise(name)
    async with session_scope() as session:
        stmt = (
            select(CTIEntity)
            .where(
                CTIEntity.entity_type.in_(("threat-actor", "campaign")),
                CTIEntity.normalised == key,
            )
            .limit(1)
        )
        entity = (await session.execute(stmt)).scalar_one_or_none()
        found = entity.as_dict() if entity else None
        entity_id = entity.id if entity else ""

    if not found:
        return {
            "known": False,
            "actor": name,
            "note": (
                "No reporting on this actor in the local corpus. Absence of "
                "reporting is not evidence the actor is inactive or unrelated."
            ),
            "corpus": await corpus_size(),
        }

    reports = await _reports_for(entity_id)
    return {
        "known": True,
        "actor": found["name"],
        "description": found["description"],
        "first_seen": found["first_seen"],
        "last_seen": found["last_seen"],
        "report_count": len(reports),
        "malware": await _co_occurring(entity_id, ("malware", "tool")),
        "techniques": await _co_occurring(entity_id, ("attack-pattern",)),
        "targets": await _co_occurring(entity_id, ("sector", "region")),
        "indicators": await _co_occurring(entity_id, ("indicator",), limit=15),
        "reports": reports[:6],
    }


async def technique_context(technique: str) -> dict[str, Any]:
    """Which reports cite a MITRE technique, and who is using it."""
    key = normalise(technique)
    async with session_scope() as session:
        stmt = (
            select(CTIEntity)
            .where(CTIEntity.entity_type == "attack-pattern", CTIEntity.normalised == key)
            .limit(1)
        )
        entity = (await session.execute(stmt)).scalar_one_or_none()
        entity_id = entity.id if entity else ""
        found = entity.as_dict() if entity else None

    if not found:
        return {
            "known": False,
            "technique": technique,
            "note": "No reporting citing this technique in the local corpus.",
        }
    return {
        "known": True,
        "technique": found["name"],
        "description": found["description"],
        "actors": await _co_occurring(entity_id, ("threat-actor", "campaign")),
        "malware": await _co_occurring(entity_id, ("malware",)),
        "reports": await _reports_for(entity_id, limit=8),
    }


async def campaign_check(days: int = 30, limit: int = 15) -> dict[str, Any]:
    """What the corpus has been reporting on lately.

    The question behind this one is "is what we are looking at part of
    something" — the single most useful thing a corpus offers an investigation
    that a per-indicator lookup cannot.
    """
    cutoff = datetime.now(UTC) - timedelta(days=max(days, 1))
    async with session_scope() as session:
        recent = select(CTIReport.id).where(CTIReport.published_at >= cutoff)
        stmt = (
            select(CTIEntity, func.count(CTIReportEntity.report_id).label("mentions"))
            .join(CTIReportEntity, CTIReportEntity.entity_id == CTIEntity.id)
            .where(
                CTIReportEntity.report_id.in_(recent),
                # Vulnerabilities belong here too: "six of the last month's
                # reports are about one CVE" is exactly the campaign signal this
                # is for, and leaving the type out made a corpus of 1,665 KEV
                # entries report that nothing had been published.
                CTIEntity.entity_type.in_(
                    (
                        "threat-actor",
                        "malware",
                        "campaign",
                        "attack-pattern",
                        "sector",
                        "vulnerability",
                    )
                ),
            )
            .group_by(CTIEntity.id)
            .order_by(func.count(CTIReportEntity.report_id).desc())
            .limit(limit)
        )
        rows = (await session.execute(stmt)).all()

    return {
        "window_days": days,
        "trending": [
            {
                "type": entity.entity_type,
                "name": entity.name,
                "mentions": mentions,
            }
            for entity, mentions in rows
        ],
        "corpus": await corpus_size(),
    }


# ── Feed bookkeeping ─────────────────────────────────────────────────────────


async def feed_state(name: str) -> dict[str, Any]:
    async with session_scope() as session:
        row = await session.get(CTIFeedState, name)
        if row is None:
            return {"name": name, "cursor": "", "consecutive_failures": 0, "items_ingested": 0}
        return {
            "name": row.name,
            "cursor": row.cursor,
            "last_run_at": row.last_run_at.isoformat() if row.last_run_at else "",
            "last_ok_at": row.last_ok_at.isoformat() if row.last_ok_at else "",
            "last_error": row.last_error,
            "consecutive_failures": row.consecutive_failures,
            "items_ingested": row.items_ingested,
        }


async def record_feed_run(
    name: str, *, ok: bool, items: int = 0, cursor: str | None = None, error: str = ""
) -> None:
    """Remember how a feed run went, successes and failures alike."""
    now = datetime.now(UTC)
    async with session_scope() as session:
        row = await session.get(CTIFeedState, name)
        if row is None:
            row = CTIFeedState(name=name)
            session.add(row)
        row.last_run_at = now
        if ok:
            row.last_ok_at = now
            row.last_error = ""
            row.consecutive_failures = 0
            row.items_ingested = (row.items_ingested or 0) + items
            if cursor is not None:
                row.cursor = cursor[:255]
        else:
            row.last_error = error[:2000]
            row.consecutive_failures = (row.consecutive_failures or 0) + 1


async def feed_health() -> list[dict[str, Any]]:
    """Every feed's standing, worst first — a silent feed is a broken one."""
    async with session_scope() as session:
        rows = (await session.execute(select(CTIFeedState))).scalars().all()
    return sorted(
        [
            {
                "name": r.name,
                "last_ok_at": r.last_ok_at.isoformat() if r.last_ok_at else "",
                "last_error": r.last_error,
                "consecutive_failures": r.consecutive_failures,
                "items_ingested": r.items_ingested,
            }
            for r in rows
        ],
        key=lambda f: -f["consecutive_failures"],
    )
