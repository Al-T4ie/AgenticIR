"""Ingestion: what gets into the corpus, and what must never.

The corpus exists to answer "have we seen this before" during an incident. That
makes a wrong entry more expensive than a missing one — a false hit on private
address space, or a two-year-old indicator presented as current, is an analyst
sent down a hole by their own tooling.

Tiered routing is the guard, and it is the part that has to be right.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from app.services import feeds


def _settings(**kw: Any) -> SimpleNamespace:
    base = {"cti_retention_days": 365, "cti_feeds": "", "abusech_api_key": ""}
    base.update(kw)
    return SimpleNamespace(**base)


@pytest.fixture(autouse=True)
def _config(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    settings = _settings()
    monkeypatch.setattr(feeds, "get_settings", lambda: settings)
    return settings


# ── Classification ───────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("185.65.135.42", "ipv4"),
        ("cdn-update-service.top", "domain"),
        ("https://evil.example/payload.bin", "url"),
        ("a" * 64, "sha256"),
        ("b" * 32, "md5"),
        ("CVE-2026-1234", "cve"),
        ("cve-2026-1234", "cve"),
        ("not an indicator", "unknown"),
        ("", "unknown"),
    ],
)
def test_indicator_kinds(value: str, expected: str) -> None:
    assert feeds.classify(value) == expected


def test_a_hash_is_not_mistaken_for_a_domain() -> None:
    """Both are long dotless-or-dotted strings; getting this wrong files a hash
    under the wrong entity type and it is never found again."""
    assert feeds.classify("d41d8cd98f00b204e9800998ecf8427e") == "md5"


# ── Routing ──────────────────────────────────────────────────────────────────
def test_private_address_space_is_dropped() -> None:
    """A public feed reporting 10.0.0.5 says nothing about *your* 10.0.0.5, and
    a corpus that answers 'known malicious' for RFC 1918 is worse than empty."""
    for address in ("10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1", "100.64.0.1"):
        decision = feeds.route({"entity_type": "indicator", "name": address})
        assert decision.tier == 0, address
        assert "routable" in decision.reason


def test_a_globally_routable_address_is_kept() -> None:
    assert feeds.route({"entity_type": "indicator", "name": "185.65.135.42"}).tier == 2


def test_an_unclassifiable_indicator_is_dropped() -> None:
    """It could never be matched against anything later, so keeping it only
    inflates the corpus count that the tools report as confidence."""
    decision = feeds.route({"entity_type": "indicator", "name": "some free text"})
    assert decision.tier == 0
    assert "classified" in decision.reason


def test_an_empty_value_is_dropped() -> None:
    assert feeds.route({"entity_type": "indicator", "name": "   "}).tier == 0


def test_stale_indicators_are_dropped(_config: SimpleNamespace) -> None:
    _config.cti_retention_days = 30
    old = datetime.now(UTC) - timedelta(days=90)
    decision = feeds.route({"entity_type": "indicator", "name": "1.2.3.4", "seen_at": old})
    assert decision.tier == 0
    assert "retention" in decision.reason


def test_an_old_vulnerability_is_kept_because_it_is_still_exploited(
    _config: SimpleNamespace,
) -> None:
    """Retention is about indicators, not facts. An address that was C2 two
    years ago has been re-allocated; CVE-2021-44228 is as exploited today as it
    was on publication, and ageing it out makes `check_indicator` answer
    "never seen" for Log4Shell.

    Found against the live CISA KEV feed, which was losing 1,399 of 1,665
    entries to a rule that should never have applied to it.
    """
    _config.cti_retention_days = 30
    ancient = datetime.now(UTC) - timedelta(days=1700)
    for entity_type, name in (
        ("vulnerability", "CVE-2021-44228"),
        ("threat-actor", "Lazarus"),
        ("malware", "Cobalt Strike"),
    ):
        decision = feeds.route({"entity_type": entity_type, "name": name, "seen_at": ancient})
        assert decision.tier == 2, f"{entity_type} must survive the retention window"


def test_retention_can_be_switched_off(_config: SimpleNamespace) -> None:
    _config.cti_retention_days = 0
    old = datetime.now(UTC) - timedelta(days=3650)
    assert feeds.route({"entity_type": "indicator", "name": "1.2.3.4", "seen_at": old}).tier == 2


def test_a_naive_timestamp_does_not_crash_the_router() -> None:
    """Feeds return dates in whatever shape they like; one bad stamp must not
    take down the whole ingest."""
    naive = datetime.now(UTC).replace(tzinfo=None)
    assert feeds.route({"entity_type": "indicator", "name": "1.2.3.4", "seen_at": naive}).tier == 2


def test_non_indicator_entities_skip_the_indicator_rules() -> None:
    """A CVE or an actor name is not an indicator and must not be run through
    address validation."""
    assert feeds.route({"entity_type": "vulnerability", "name": "CVE-2026-1234"}).tier == 2
    assert feeds.route({"entity_type": "threat-actor", "name": "ShinyHunters"}).tier == 2


def test_narrative_sources_are_routed_for_analysis_not_bulk_ingest() -> None:
    decision = feeds.route({"entity_type": "report", "name": "A blog post", "narrative": True})
    assert decision.tier == 1


def test_dropped_items_are_counted_by_reason_not_discarded_silently() -> None:
    """A feed that quietly bins half its input is indistinguishable from one
    that is broken."""
    kept, dropped = feeds.apply_routing(
        [
            {"entity_type": "indicator", "name": "185.65.135.42"},
            {"entity_type": "indicator", "name": "10.0.0.1"},
            {"entity_type": "indicator", "name": "192.168.0.1"},
            {"entity_type": "indicator", "name": "gibberish here"},
        ]
    )
    assert len(kept) == 1
    assert sum(dropped.values()) == 3
    assert len(dropped) == 2, "two distinct reasons, counted separately"


def test_routing_stamps_the_tier_onto_what_it_keeps() -> None:
    kept, _ = feeds.apply_routing([{"entity_type": "indicator", "name": "1.1.1.1"}])
    assert kept[0]["tier"] == 2


# ── Feed selection ───────────────────────────────────────────────────────────
def test_feeds_needing_a_key_are_skipped_without_one(_config: SimpleNamespace) -> None:
    """Skipped, not failed: an operator with no abuse.ch account should still
    get CISA KEV rather than a wall of auth errors."""
    names = [f.name for f in feeds.enabled_feeds()]
    assert "cisa-kev" in names
    assert "threatfox" not in names


def test_a_key_unlocks_its_feeds(_config: SimpleNamespace) -> None:
    _config.abusech_api_key = "test-key"
    names = [f.name for f in feeds.enabled_feeds()]
    assert {"cisa-kev", "threatfox", "urlhaus"} <= set(names)


def test_the_feed_list_can_be_narrowed(_config: SimpleNamespace) -> None:
    _config.cti_feeds = "cisa-kev"
    assert [f.name for f in feeds.enabled_feeds()] == ["cisa-kev"]


# ── Parsing real feed shapes ─────────────────────────────────────────────────
async def test_kev_becomes_vulnerability_entities(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake(url: str, **_kw: Any) -> dict[str, Any]:  # noqa: ARG001
        return {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-1234",
                    "vendorProject": "Acme",
                    "product": "Gateway",
                    "vulnerabilityName": "Auth bypass",
                    "dateAdded": "2026-08-01",
                    "dueDate": "2026-08-22",
                    "shortDescription": "Allows unauthenticated access.",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "", "vendorProject": "junk"},
            ]
        }

    monkeypatch.setattr(feeds, "_get_json", _fake)
    items = await feeds.fetch_kev()

    assert len(items) == 1, "a row with no CVE id is not an entity"
    item = items[0]
    assert item["entity_type"] == "vulnerability"
    assert item["name"] == "CVE-2026-1234"
    assert "Acme Gateway" in item["description"]
    assert "known-exploited" in item["tags"]
    assert "known" in item["tags"], "ransomware use is worth its own tag"
    assert item["seen_at"].year == 2026


async def test_threatfox_carries_the_malware_family(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fake(url: str, payload: dict, **_kw: Any) -> dict[str, Any]:  # noqa: ARG001
        return {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "185.65.135.42",
                    "malware_printable": "Cobalt Strike",
                    "threat_type_desc": "C2 server",
                    "first_seen": "2026-08-01 10:00:00",
                    "confidence_level": 90,
                    "tags": ["c2"],
                }
            ],
        }

    monkeypatch.setattr(feeds, "_post_json", _fake)
    items = await feeds.fetch_threatfox()
    assert items[0]["kind"] == "ipv4"
    assert items[0]["malware"] == "Cobalt Strike"
    assert items[0]["confidence"] == 90


async def test_a_refusing_feed_raises_rather_than_ingesting_nothing_quietly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`query_status: no_result` with an empty list looks identical to success,
    and would silently mark the feed healthy."""

    async def _fake(url: str, payload: dict, **_kw: Any) -> dict[str, Any]:  # noqa: ARG001
        return {"query_status": "illegal_auth", "data": []}

    monkeypatch.setattr(feeds, "_post_json", _fake)
    with pytest.raises(RuntimeError, match="illegal_auth"):
        await feeds.fetch_threatfox()


# ── Running a feed end to end ────────────────────────────────────────────────
@pytest.fixture
def run(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {"batches": [], "runs": []}

    async def _ingest(**kw: Any) -> int:
        state["batches"].append(kw)
        return len(kw.get("items") or [])

    async def _record(name: str, **kw: Any) -> None:
        state["runs"].append({"name": name, **kw})

    monkeypatch.setattr(feeds.cti, "ingest_batch", _ingest)
    monkeypatch.setattr(feeds.cti, "record_feed_run", _record)
    return state


def _feed(items: list[dict[str, Any]], *, boom: bool = False) -> feeds.Feed:
    async def _fetch() -> list[dict[str, Any]]:
        if boom:
            raise RuntimeError("provider is down")
        return items

    return feeds.Feed(name="test-feed", layer=4, description="Test", fetch=_fetch)


async def test_a_feed_run_ingests_what_survives_routing(run: dict[str, Any]) -> None:
    result = await feeds.run_feed(
        _feed(
            [
                {"entity_type": "indicator", "name": "185.65.135.42", "kind": "ipv4"},
                {"entity_type": "indicator", "name": "10.0.0.1", "kind": "ipv4"},
            ]
        )
    )
    assert result["ok"] is True
    assert result["fetched"] == 2
    assert result["dropped"] == {"not globally routable": 1}
    assert len(run["batches"][0]["items"]) == 1


async def test_a_named_malware_family_becomes_its_own_entity(run: dict[str, Any]) -> None:
    """The association is the intelligence. An indicator with no context is a
    string somebody once disliked."""
    await feeds.run_feed(
        _feed([{"entity_type": "indicator", "name": "1.2.3.4", "malware": "Cobalt Strike"}])
    )
    kinds = [(i["entity_type"], i["name"]) for i in run["batches"][0]["items"]]
    assert ("indicator", "1.2.3.4") in kinds
    assert ("malware", "Cobalt Strike") in kinds


async def test_a_dead_feed_is_recorded_as_failed_not_as_an_empty_success(
    run: dict[str, Any],
) -> None:
    """A feed failing for a week must not look like a quiet one — 'no
    intelligence' reads as 'nothing to worry about'."""
    result = await feeds.run_feed(_feed([], boom=True))
    assert result["ok"] is False
    assert "provider is down" in result["error"]
    assert run["runs"][0]["ok"] is False
    assert run["batches"] == [], "nothing is written when the fetch failed"


async def test_a_feed_run_never_raises(run: dict[str, Any]) -> None:
    assert (await feeds.run_feed(_feed([], boom=True)))["ok"] is False


async def test_an_enormous_batch_is_capped_and_says_so(run: dict[str, Any]) -> None:
    huge = [
        {"entity_type": "indicator", "name": f"185.65.{i // 256}.{i % 256}", "kind": "ipv4"}
        for i in range(feeds._MAX_ITEMS + 50)
    ]
    result = await feeds.run_feed(_feed(huge))
    assert result["truncated"] > 0
    assert len(run["batches"][0]["items"]) <= feeds._MAX_ITEMS


async def test_the_batch_identity_is_stable_within_the_hour(run: dict[str, Any]) -> None:
    """Two runs in the same hour must update one report, not create two — a
    corpus that double-counts turns 'seen in 9 reports' into a measure of how
    often the poller ran."""
    now = datetime(2026, 8, 16, 11, 30, tzinfo=UTC)
    feed = _feed([{"entity_type": "indicator", "name": "1.2.3.4"}])
    await feeds.run_feed(feed, now=now)
    await feeds.run_feed(feed, now=now.replace(minute=55))
    assert run["batches"][0]["external_id"] == run["batches"][1]["external_id"]
