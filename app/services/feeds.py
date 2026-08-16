"""Where the corpus comes from, and what never makes it in.

Adapted from the Cognitive CTI project's ingestion stage, minus OpenCTI. That
project used OpenCTI to aggregate and normalise before this step; here the feeds
are read directly, because everything AgenticIR asks of intelligence during an
incident is a SQL query and none of it needs a STIX graph. The layering and the
tiered routing are kept, because those are the parts that make it work.

**Tiered routing is the whole trick.** The original found that processing every
item — roughly 5,000 per cycle — did not merely cost time, it made the output
worse: small models hallucinated more as volume rose. Routing cut that to 50–80
items worth reasoning about. The same logic applies here for a different reason:
a corpus stuffed with unroutable addresses and stale indicators answers "have we
seen this" with noise, and an analyst who is misled twice stops asking.

    tier 1  narrative intelligence — worth a model call
    tier 2  structured feed data — ingest as metadata, no model
    tier 0  dropped, with the reason recorded

Nothing here is dropped silently. A feed that quietly discards half its input is
indistinguishable from a feed that is broken.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import httpx

from app.config import get_settings
from app.observability import get_logger
from app.services import cti

log = get_logger(__name__)

_TIMEOUT = 30.0
# One feed run must not be able to write an unbounded corpus. Feeds publish
# bulk dumps and an unlucky day would otherwise turn one tick into an hour.
_MAX_ITEMS = 2000

_SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
_MD5 = re.compile(r"^[a-fA-F0-9]{32}$")
_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)


# ── What kind of thing is this ───────────────────────────────────────────────
def classify(value: str) -> str:
    """`ipv4` | `domain` | `url` | `sha256` | `md5` | `cve` | `unknown`."""
    raw = str(value or "").strip()
    if not raw:
        return "unknown"
    if raw.lower().startswith(("http://", "https://")):
        return "url"
    if _CVE.match(raw):
        return "cve"
    if _SHA256.match(raw):
        return "sha256"
    if _MD5.match(raw):
        return "md5"
    try:
        ipaddress.ip_address(raw.split(":")[0])
    except ValueError:
        pass
    else:
        return "ipv4"
    if _DOMAIN.match(raw):
        return "domain"
    return "unknown"


# ── Tiered routing ───────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Routed:
    tier: int
    reason: str


def route(item: dict[str, Any], *, now: datetime | None = None) -> Routed:
    """Decide what an incoming item is worth. Tier 0 means dropped.

    The drop rules are the ones that would otherwise poison a lookup:

    * **Unroutable addresses.** RFC 1918, loopback and CGNAT space appearing in
      a public feed says nothing about *your* 10.0.0.5, and a corpus that
      answers "known malicious" for private space is worse than an empty one.
    * **Unparseable indicators.** A value we cannot classify cannot be matched
      against anything later, so storing it only inflates the corpus count.
    * **Stale entries.** An indicator last reported two years ago answers a
      question nobody asked; the retention window keeps the corpus about now.
    """
    now = now or datetime.now(UTC)
    entity_type = str(item.get("entity_type") or "indicator")
    name = str(item.get("name") or "").strip()

    if not name:
        return Routed(0, "empty value")

    if entity_type == "indicator":
        kind = str(item.get("kind") or "") or classify(name)
        if kind == "unknown":
            return Routed(0, "indicator could not be classified")
        if kind == "ipv4":
            try:
                addr = ipaddress.ip_address(name.split(":")[0])
            except ValueError:
                return Routed(0, "malformed address")
            if not addr.is_global:
                return Routed(0, "not globally routable")

    # Retention applies to indicators and nothing else. An address that was
    # command-and-control two years ago has almost certainly been re-allocated,
    # so ageing it out keeps the corpus about the present. A *vulnerability* is
    # the opposite: CVE-2021-44228 is as exploited today as it was on the day it
    # was published, and dropping it would have `check_indicator` answer "never
    # seen" for Log4Shell. Actors and malware families are durable for the same
    # reason. This rule was written the wrong way round first and only the live
    # KEV feed exposed it — 1,399 of 1,665 entries were being discarded.
    if entity_type == "indicator":
        seen = item.get("seen_at")
        if isinstance(seen, datetime):
            seen = seen if seen.tzinfo else seen.replace(tzinfo=UTC)
            window = get_settings().cti_retention_days
            if window > 0 and (now - seen).days > window:
                return Routed(0, f"indicator older than the {window}-day retention window")

    # Narrative sources need a model to be useful; structured ones already
    # carry their own tagging and would only be paraphrased by one.
    if item.get("narrative"):
        return Routed(1, "narrative intelligence")
    return Routed(2, "structured feed data")


def apply_routing(
    items: list[dict[str, Any]], *, now: datetime | None = None
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Split a batch into what is kept and a tally of why the rest was not."""
    kept: list[dict[str, Any]] = []
    dropped: dict[str, int] = {}
    for item in items:
        decision = route(item, now=now)
        if decision.tier == 0:
            dropped[decision.reason] = dropped.get(decision.reason, 0) + 1
            continue
        kept.append({**item, "tier": decision.tier})
    return kept, dropped


# ── Feed definitions ─────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Feed:
    name: str
    #: 1 vendor · 2 research · 3 sector · 4 IOC feed · 5 actor channel
    layer: int
    description: str
    fetch: Callable[[], Coroutine[Any, Any, list[dict[str, Any]]]]
    #: Settings attribute holding an API key. Empty means the feed needs none.
    key_setting: str = ""
    tags: list[str] = field(default_factory=list)


async def _get_json(url: str, **kw: Any) -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        response = await client.get(url, **kw)
        response.raise_for_status()
        return response.json()


async def _post_json(url: str, payload: dict[str, Any], **kw: Any) -> Any:
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        response = await client.post(url, json=payload, **kw)
        response.raise_for_status()
        return response.json()


def _parse_date(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00").replace(" UTC", "")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            parsed = datetime.fromisoformat(text) if fmt is None else datetime.strptime(text, fmt)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


# ── CISA Known Exploited Vulnerabilities ─────────────────────────────────────
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def fetch_kev() -> list[dict[str, Any]]:
    """CVEs with confirmed in-the-wild exploitation.

    The highest-signal free feed there is, and the reason it is worth having
    locally: "this CVE is on KEV" turns a patch-window conversation into an
    incident, and it is exactly the fact a triage specialist should not have to
    take on trust from a model's memory.
    """
    data = await _get_json(KEV_URL)
    out: list[dict[str, Any]] = []
    for row in (data or {}).get("vulnerabilities", []) or []:
        cve = str(row.get("cveID") or "").strip()
        if not cve:
            continue
        added = _parse_date(row.get("dateAdded"))
        vendor = str(row.get("vendorProject") or "")
        product = str(row.get("product") or "")
        out.append(
            {
                "entity_type": "vulnerability",
                "name": cve,
                "kind": "cve",
                "description": (
                    f"{vendor} {product}: {row.get('vulnerabilityName', '')}. "
                    f"Known exploited; CISA due date {row.get('dueDate', 'n/a')}. "
                    f"{row.get('shortDescription', '')}"
                ).strip(),
                "seen_at": added,
                "confidence": 100,
                "tags": ["known-exploited", "kev"]
                + (
                    [row.get("knownRansomwareCampaignUse", "").lower()]
                    if row.get("knownRansomwareCampaignUse", "").lower() == "known"
                    else []
                ),
            }
        )
    return out


# ── abuse.ch ThreatFox ───────────────────────────────────────────────────────
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


async def fetch_threatfox() -> list[dict[str, Any]]:
    """Recent IOCs with the malware family that they belong to."""
    key = get_settings().abusech_api_key
    headers = {"Auth-Key": key} if key else {}
    data = await _post_json(THREATFOX_URL, {"query": "get_iocs", "days": 1}, headers=headers)
    if str((data or {}).get("query_status")) != "ok":
        raise RuntimeError(f"ThreatFox refused the query: {(data or {}).get('query_status')}")

    out: list[dict[str, Any]] = []
    for row in (data or {}).get("data", []) or []:
        value = str(row.get("ioc") or "").strip()
        if not value:
            continue
        malware = str(row.get("malware_printable") or "").strip()
        seen = _parse_date(row.get("first_seen"))
        out.append(
            {
                "entity_type": "indicator",
                "name": value,
                "kind": classify(value),
                "description": (
                    f"{row.get('threat_type_desc') or row.get('threat_type') or 'IOC'}"
                    + (f" · {malware}" if malware else "")
                ),
                "seen_at": seen,
                "confidence": int(row.get("confidence_level") or 50),
                "tags": [t for t in (row.get("tags") or []) if t][:6],
                "malware": malware,
            }
        )
    return out


# ── abuse.ch URLhaus ─────────────────────────────────────────────────────────
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


async def fetch_urlhaus() -> list[dict[str, Any]]:
    """URLs actively serving malware."""
    key = get_settings().abusech_api_key
    headers = {"Auth-Key": key} if key else {}
    async with httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=True) as client:
        response = await client.post(URLHAUS_URL, data={"limit": "500"}, headers=headers)
        response.raise_for_status()
        data = response.json()
    if str((data or {}).get("query_status")) != "ok":
        raise RuntimeError(f"URLhaus refused the query: {(data or {}).get('query_status')}")

    out: list[dict[str, Any]] = []
    for row in (data or {}).get("urls", []) or []:
        url = str(row.get("url") or "").strip()
        if not url:
            continue
        out.append(
            {
                "entity_type": "indicator",
                "name": url,
                "kind": "url",
                "description": f"Malware distribution URL, status {row.get('url_status', '?')}",
                "seen_at": _parse_date(row.get("date_added")),
                "confidence": 75,
                "tags": [t for t in (row.get("tags") or []) if t][:6],
            }
        )
        # The host on its own is what an investigation usually has — a proxy log
        # gives you the domain, not the full path the sample was served from.
        host = str(row.get("host") or "").strip()
        if host and classify(host) in {"domain", "ipv4"}:
            out.append(
                {
                    "entity_type": "indicator",
                    "name": host,
                    "kind": classify(host),
                    "description": "Host serving malware (URLhaus)",
                    "seen_at": _parse_date(row.get("date_added")),
                    "confidence": 60,
                }
            )
    return out


FEEDS: list[Feed] = [
    Feed(
        name="cisa-kev",
        layer=1,
        description="CISA Known Exploited Vulnerabilities",
        fetch=fetch_kev,
    ),
    Feed(
        name="threatfox",
        layer=4,
        description="abuse.ch ThreatFox IOCs",
        fetch=fetch_threatfox,
        key_setting="abusech_api_key",
    ),
    Feed(
        name="urlhaus",
        layer=4,
        description="abuse.ch URLhaus malware URLs",
        fetch=fetch_urlhaus,
        key_setting="abusech_api_key",
    ),
]


def enabled_feeds() -> list[Feed]:
    """Feeds that are switched on and have whatever credential they need."""
    settings = get_settings()
    wanted = {f.strip().lower() for f in settings.cti_feeds.split(",") if f.strip()}
    out = []
    for feed in FEEDS:
        if wanted and feed.name not in wanted:
            continue
        if feed.key_setting and not getattr(settings, feed.key_setting, ""):
            # Named rather than skipped in silence: an operator who thinks
            # ThreatFox is running and has no key gets told once per boot.
            log.info(
                "feeds.skipped_no_key",
                feed=feed.name,
                needs=feed.key_setting.upper(),
                hint="register free at auth.abuse.ch",
            )
            continue
        out.append(feed)
    return out


# ── Running one ──────────────────────────────────────────────────────────────
async def run_feed(feed: Feed, *, now: datetime | None = None) -> dict[str, Any]:
    """Fetch, route and ingest a single feed. Never raises."""
    now = now or datetime.now(UTC)
    try:
        raw = await feed.fetch()
    except Exception as exc:  # noqa: BLE001 — one dead feed must not stop the rest
        await cti.record_feed_run(feed.name, ok=False, error=str(exc))
        log.warning("feeds.fetch_failed", feed=feed.name, error=str(exc))
        return {"feed": feed.name, "ok": False, "error": str(exc), "ingested": 0}

    kept, dropped = apply_routing(raw, now=now)
    truncated = max(0, len(kept) - _MAX_ITEMS)
    kept = kept[:_MAX_ITEMS]

    items: list[dict[str, Any]] = list(kept)
    # A malware family named by the feed is an entity in its own right, and the
    # association is the thing worth having — an indicator with no context is
    # just a string that someone once disliked.
    for entry in kept:
        family = str(entry.get("malware") or "").strip()
        if family:
            items.append(
                {
                    "entity_type": "malware",
                    "name": family,
                    "description": f"Malware family reported by {feed.name}",
                    "seen_at": entry.get("seen_at"),
                    "confidence": 70,
                }
            )

    stamp = now.strftime("%Y-%m-%dT%H")
    try:
        written = await cti.ingest_batch(
            external_id=f"{feed.name}:{stamp}",
            title=f"{feed.description} — {now:%Y-%m-%d %H:00 UTC}",
            source=feed.name,
            layer=feed.layer,
            items=items,
            published_at=now,
            severity="high" if feed.layer <= 2 else "medium",
        )
    except Exception as exc:  # noqa: BLE001
        await cti.record_feed_run(feed.name, ok=False, error=str(exc))
        log.error("feeds.ingest_failed", feed=feed.name, error=str(exc))
        return {"feed": feed.name, "ok": False, "error": str(exc), "ingested": 0}

    await cti.record_feed_run(feed.name, ok=True, items=written, cursor=stamp)
    result = {
        "feed": feed.name,
        "ok": True,
        "fetched": len(raw),
        "ingested": written,
        "dropped": dropped,
        "truncated": truncated,
    }
    if truncated:
        log.warning("feeds.truncated", feed=feed.name, dropped=truncated, cap=_MAX_ITEMS)
    log.info("feeds.ingested", **{k: v for k, v in result.items() if k != "dropped"})
    return result


async def refresh() -> dict[str, Any]:
    """Run every enabled feed once."""
    feeds = enabled_feeds()
    if not feeds:
        return {"feeds": 0, "ingested": 0, "results": []}
    results = [await run_feed(feed) for feed in feeds]
    return {
        "feeds": len(results),
        "ingested": sum(int(r.get("ingested") or 0) for r in results),
        "failed": [r["feed"] for r in results if not r["ok"]],
        "results": results,
    }
