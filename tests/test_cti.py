"""The corpus, against a real database.

These run on SQLite rather than mocks because the whole value of this module is
in its queries — the co-occurrence join that turns "an indicator" into "an
indicator every report links to ShinyHunters" is exactly the thing a mock would
assert into existence without proving.

The rule under test throughout: **an indicator we have not seen returns
unknown, never clean.** A fabricated clean verdict is how a real detection gets
suppressed, and it is worse than no answer because it arrives with the
authority of a lookup.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.db.models import Base
from app.services import cti


@pytest.fixture
async def db(monkeypatch: pytest.MonkeyPatch):
    """A real, empty corpus per test."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    @asynccontextmanager
    async def _scope():
        async with maker() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    monkeypatch.setattr(cti, "session_scope", _scope)
    yield
    await engine.dispose()


def _ago(days: int) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


async def seed(**kw: Any) -> int:
    """One feed batch: an indicator, an actor, a technique, all linked."""
    return await cti.ingest_batch(
        external_id=kw.get("external_id", "test:1"),
        title=kw.get("title", "ThreatFox batch"),
        source=kw.get("source", "threatfox"),
        layer=kw.get("layer", 4),
        published_at=kw.get("published_at", _ago(1)),
        items=kw.get(
            "items",
            [
                {"entity_type": "indicator", "name": "185.65.135.42", "kind": "ipv4"},
                {"entity_type": "threat-actor", "name": "ShinyHunters"},
                {"entity_type": "attack-pattern", "name": "T1567.002"},
                {"entity_type": "malware", "name": "Cobalt Strike"},
            ],
        ),
    )


# ── The rule that matters most ───────────────────────────────────────────────
async def test_an_unseen_indicator_is_unknown_and_says_so_in_words(db) -> None:
    await seed()
    result = await cti.lookup_indicator("203.0.113.99")
    assert result["known"] is False
    assert result["verdict"] == "unknown"
    assert "NOT a clean verdict" in result["note"]


async def test_an_empty_corpus_reports_its_own_emptiness(db) -> None:
    """Otherwise 'not found' against a corpus that has ingested nothing reads
    exactly like 'not found' against a corpus that knows ten thousand things."""
    result = await cti.lookup_indicator("1.2.3.4")
    assert result["known"] is False
    assert result["corpus"]["reports"] == 0


async def test_the_tool_wording_flags_an_empty_corpus(db, monkeypatch) -> None:
    from app.tools import cti as cti_tools

    monkeypatch.setattr(cti_tools.cti, "lookup_indicator", cti.lookup_indicator)
    text = await cti_tools._check_indicator("1.2.3.4")
    assert "EMPTY" in text
    assert "not a clean" in text.lower()


async def test_a_known_indicator_comes_back_with_its_provenance(db) -> None:
    await seed()
    result = await cti.lookup_indicator("185.65.135.42")
    assert result["known"] is True
    assert result["verdict"] == "reported-malicious"
    assert result["sources"] == ["threatfox"]
    assert result["best_layer"] == 4
    assert "IOC feed" in result["best_layer_meaning"]


async def test_a_cve_is_findable_by_the_indicator_lookup(db) -> None:
    """A CVE is stored as a `vulnerability`, not an `indicator`, and searching
    only the latter made the entire CISA KEV catalogue invisible to the tool
    that exists to query it — 1,665 entities in the corpus and
    `check_indicator("CVE-2021-44228")` answering "never seen".

    Found end to end against the live feed; no unit test caught it, because the
    seeded fixtures used exactly the types the query already looked for.
    """
    await seed(
        source="cisa-kev",
        layer=1,
        items=[
            {
                "entity_type": "vulnerability",
                "name": "CVE-2021-44228",
                "kind": "cve",
                "description": "Apache Log4j2 RCE, known exploited.",
            }
        ],
    )
    result = await cti.lookup_indicator("CVE-2021-44228")
    assert result["known"] is True
    assert result["verdict"] == "known-exploited", "a CVE is not 'malicious infrastructure'"
    assert result["entity_type"] == "vulnerability"


async def test_a_vulnerability_reads_differently_from_an_indicator(db) -> None:
    from app.tools import cti as cti_tools

    await seed(items=[{"entity_type": "vulnerability", "name": "CVE-2021-44228", "kind": "cve"}])
    text = await cti_tools._check_indicator("CVE-2021-44228")
    assert "KNOWN EXPLOITED" in text
    assert "REPORTED MALICIOUS" not in text


async def test_campaign_check_sees_vulnerabilities(db) -> None:
    """Leaving the type out of the trend query made a corpus of 1,665 KEV
    entries report that nothing had been published."""
    await seed(
        published_at=_ago(1),
        items=[{"entity_type": "vulnerability", "name": "CVE-2026-1234", "kind": "cve"}],
    )
    names = [t["name"] for t in (await cti.campaign_check(days=30))["trending"]]
    assert "CVE-2026-1234" in names


# ── Lookup robustness ────────────────────────────────────────────────────────
async def test_lookup_is_case_and_whitespace_insensitive(db) -> None:
    """An analyst pastes `CDN-Update-Service.TOP`; the feed stored it lowercase.
    A case-sensitive miss reads as 'never seen' — the worst wrong answer here."""
    await seed(
        items=[{"entity_type": "indicator", "name": "cdn-update-service.top", "kind": "domain"}]
    )
    for typed in ("CDN-Update-Service.TOP", "  cdn-update-service.top  ", "Cdn-Update-Service.Top"):
        assert (await cti.lookup_indicator(typed))["known"] is True, typed


async def test_an_empty_lookup_is_not_a_database_query(db) -> None:
    assert (await cti.lookup_indicator("   "))["known"] is False


# ── The join that makes it intelligence ──────────────────────────────────────
async def test_an_indicator_carries_the_actor_it_appears_alongside(db) -> None:
    """This is the entire point of a corpus over a per-lookup vendor API."""
    await seed()
    result = await cti.lookup_indicator("185.65.135.42")
    names = {a["name"] for a in result["associated"]}
    assert "ShinyHunters" in names
    assert "Cobalt Strike" in names


async def test_an_entity_is_not_associated_with_itself(db) -> None:
    await seed()
    result = await cti.lookup_indicator("185.65.135.42")
    assert "185.65.135.42" not in {a["name"] for a in result["associated"]}


async def test_association_strength_reflects_how_often_they_co_occur(db) -> None:
    """One shared report is a coincidence; five is a pattern, and the ranking
    has to say which is which."""
    for i in range(3):
        await seed(
            external_id=f"batch:{i}",
            items=[
                {"entity_type": "indicator", "name": "185.65.135.42", "kind": "ipv4"},
                {"entity_type": "threat-actor", "name": "ShinyHunters"},
            ],
        )
    await seed(
        external_id="batch:odd",
        items=[
            {"entity_type": "indicator", "name": "185.65.135.42", "kind": "ipv4"},
            {"entity_type": "threat-actor", "name": "Lapsus$"},
        ],
    )
    result = await cti.lookup_indicator("185.65.135.42")
    top = result["associated"][0]
    assert top["name"] == "ShinyHunters"
    assert top["shared_reports"] == 3


# ── Actors and techniques ────────────────────────────────────────────────────
async def test_an_actor_profile_assembles_from_co_occurrence(db) -> None:
    await seed()
    profile = await cti.actor_profile("ShinyHunters")
    assert profile["known"] is True
    assert {m["name"] for m in profile["malware"]} == {"Cobalt Strike"}
    assert {t["name"] for t in profile["techniques"]} == {"T1567.002"}
    assert {i["name"] for i in profile["indicators"]} == {"185.65.135.42"}


async def test_an_unknown_actor_does_not_imply_an_uninvolved_one(db) -> None:
    await seed()
    profile = await cti.actor_profile("Scattered Spider")
    assert profile["known"] is False
    assert "not evidence" in profile["note"]


async def test_technique_context_names_who_uses_it(db) -> None:
    await seed()
    result = await cti.technique_context("T1567.002")
    assert result["known"] is True
    assert "ShinyHunters" in {a["name"] for a in result["actors"]}


# ── Corpus behaviour over repeated ingests ───────────────────────────────────
async def test_re_ingesting_a_batch_updates_it_rather_than_duplicating(db) -> None:
    """A corpus that double-counts turns 'reported by 9 sources' into a measure
    of how often the scheduler ran."""
    await seed(external_id="same:id")
    await seed(external_id="same:id")
    assert (await cti.corpus_size())["reports"] == 1
    assert (await cti.lookup_indicator("185.65.135.42"))["report_count"] == 1


async def test_an_entity_seen_again_widens_its_window_rather_than_duplicating(db) -> None:
    await seed(external_id="old", published_at=_ago(30))
    await seed(external_id="new", published_at=_ago(1))

    result = await cti.lookup_indicator("185.65.135.42")
    assert result["report_count"] == 2
    first = datetime.fromisoformat(result["first_seen"])
    last = datetime.fromisoformat(result["last_seen"])
    assert (last - first).days >= 28, "the window must span both sightings"


async def test_entities_of_different_types_can_share_a_name(db) -> None:
    """A malware family and a campaign are routinely given the same name, and
    collapsing them would merge two different things into one profile."""
    await seed(
        items=[
            {"entity_type": "malware", "name": "Anubis"},
            {"entity_type": "campaign", "name": "Anubis"},
        ]
    )
    assert (await cti.corpus_size())["entities"] == 2


async def test_an_empty_batch_writes_nothing(db) -> None:
    assert await cti.ingest_batch(external_id="x", title="t", source="s", layer=4, items=[]) == 0
    assert (await cti.corpus_size())["reports"] == 0


async def test_a_nameless_item_is_skipped_not_stored_blank(db) -> None:
    written = await cti.ingest_batch(
        external_id="x",
        title="t",
        source="s",
        layer=4,
        items=[
            {"entity_type": "indicator", "name": "  "},
            {"entity_type": "indicator", "name": "1.1.1.1"},
        ],
    )
    assert written == 1


# ── Campaign view ────────────────────────────────────────────────────────────
async def test_campaign_check_ranks_what_is_being_reported_now(db) -> None:
    for i in range(3):
        await seed(
            external_id=f"recent:{i}",
            published_at=_ago(2),
            items=[{"entity_type": "threat-actor", "name": "ShinyHunters"}],
        )
    await seed(
        external_id="ancient",
        published_at=_ago(300),
        items=[{"entity_type": "threat-actor", "name": "OldGang"}],
    )
    result = await cti.campaign_check(days=30)
    names = [t["name"] for t in result["trending"]]
    assert names[0] == "ShinyHunters"
    assert "OldGang" not in names, "outside the window is outside the answer"


async def test_campaign_check_on_an_empty_corpus_returns_nothing_not_an_error(db) -> None:
    assert (await cti.campaign_check())["trending"] == []


# ── Feed health ──────────────────────────────────────────────────────────────
async def test_a_failing_feed_accumulates_failures(db) -> None:
    await cti.record_feed_run("threatfox", ok=False, error="401 unauthorised")
    await cti.record_feed_run("threatfox", ok=False, error="401 unauthorised")
    state = await cti.feed_state("threatfox")
    assert state["consecutive_failures"] == 2
    assert "401" in state["last_error"]


async def test_a_success_clears_the_failure_streak(db) -> None:
    await cti.record_feed_run("threatfox", ok=False, error="boom")
    await cti.record_feed_run("threatfox", ok=True, items=40, cursor="2026-08-16T11")
    state = await cti.feed_state("threatfox")
    assert state["consecutive_failures"] == 0
    assert state["last_error"] == ""
    assert state["items_ingested"] == 40


async def test_ingest_counts_accumulate_across_runs(db) -> None:
    await cti.record_feed_run("kev", ok=True, items=10)
    await cti.record_feed_run("kev", ok=True, items=5)
    assert (await cti.feed_state("kev"))["items_ingested"] == 15


async def test_health_puts_the_worst_feed_first(db) -> None:
    await cti.record_feed_run("healthy", ok=True, items=1)
    await cti.record_feed_run("broken", ok=False, error="down")
    await cti.record_feed_run("broken", ok=False, error="down")
    assert (await cti.feed_health())[0]["name"] == "broken"


async def test_an_unseen_feed_has_a_usable_default_state(db) -> None:
    state = await cti.feed_state("never-run")
    assert state["consecutive_failures"] == 0
    assert state["cursor"] == ""
