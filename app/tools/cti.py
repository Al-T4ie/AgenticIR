"""Threat intelligence, as tools a specialist can call mid-investigation.

These query the local corpus rather than a vendor API, which matters for two
reasons beyond latency. It means an investigation can ask "have we seen this
before" — a question no per-lookup vendor call answers. And it means the answer
is reproducible: the report cites what the corpus held at the time, not whatever
a third party happened to return that afternoon.

Every one of these returns prose rather than JSON. The consumer is a model
reading tool output in a message history, and a paragraph that says "not present
— this is not a clean verdict" survives summarisation in a way a
`{"known": false}` does not.
"""

from __future__ import annotations

from typing import Any

from langchain_core.tools import StructuredTool

from app.observability import TOOL_CALLS, get_logger
from app.services import cti

log = get_logger(__name__)


def _corpus_note(payload: dict[str, Any]) -> str:
    """Say how much the corpus knows, when it does not know this.

    An empty corpus and a populated one that has never seen an indicator are
    completely different facts, and only one of them is about the indicator.
    """
    size = payload.get("corpus") or {}
    reports = int(size.get("reports") or 0)
    if reports == 0:
        return (
            "\n\nNote: the local intelligence corpus is EMPTY — no feeds have been "
            "ingested yet. This lookup could not have found anything. Do not treat "
            "it as evidence either way."
        )
    return (
        f"\n\n(Corpus holds {reports} report(s) and "
        f"{int(size.get('entities') or 0)} entities; last ingest {size.get('last_ingest') or 'never'}.)"
    )


def _entities(rows: list[dict[str, Any]], label: str) -> str:
    if not rows:
        return ""
    parts = [f"{r['name']} ({r.get('shared_reports', '?')} shared)" for r in rows[:8]]
    return f"\n{label}: " + ", ".join(parts)


async def _check_indicator(indicator: str) -> str:
    result = await cti.lookup_indicator(indicator)
    if not result.get("known"):
        TOOL_CALLS.labels(tool="check_indicator", outcome="ok").inc()
        return (
            f"{indicator} — NOT FOUND in the threat intelligence corpus.\n"
            "This is an 'unknown' verdict, NOT a clean one: it means no ingested "
            "source has reported this indicator. It is not evidence the indicator "
            "is benign." + _corpus_note(result)
        )

    TOOL_CALLS.labels(tool="check_indicator", outcome="ok").inc()
    headline = (
        "KNOWN EXPLOITED — this CVE is on a confirmed-exploitation catalogue"
        if result.get("verdict") == "known-exploited"
        else "REPORTED MALICIOUS in the corpus"
    )
    lines = [
        f"{indicator} — {headline}.",
        f"Type: {result.get('kind') or result.get('entity_type') or 'unknown'}",
        f"Reported by {result.get('report_count')} report(s) from: "
        f"{', '.join(result.get('sources') or []) or 'unknown source'}",
        f"Highest-trust source layer: {result.get('best_layer')} "
        f"({result.get('best_layer_meaning')})",
        f"First seen {result.get('first_seen') or 'unknown'}, "
        f"last seen {result.get('last_seen') or 'unknown'}",
    ]
    if result.get("description"):
        lines.append(f"Context: {result['description']}")
    associated = result.get("associated") or []
    if associated:
        lines.append(
            "Associated with: "
            + ", ".join(f"{a['name']} [{a['entity_type']}]" for a in associated[:8])
        )
    for report in (result.get("reports") or [])[:4]:
        lines.append(f"  · {report['source']}: {report['title'][:120]}")
    return "\n".join(lines)


async def _actor_profile(actor: str) -> str:
    result = await cti.actor_profile(actor)
    TOOL_CALLS.labels(tool="actor_profile", outcome="ok").inc()
    if not result.get("known"):
        return (
            f"No reporting on '{actor}' in the local corpus. Absence of reporting is "
            "not evidence the actor is uninvolved — it means this corpus has nothing "
            "on them." + _corpus_note(result)
        )

    lines = [
        f"{result['actor']} — {result.get('report_count')} report(s) in the corpus.",
        f"First seen {result.get('first_seen') or 'unknown'}, "
        f"last seen {result.get('last_seen') or 'unknown'}",
    ]
    if result.get("description"):
        lines.append(result["description"][:400])
    lines.append(_entities(result.get("malware") or [], "Tooling/malware").strip())
    lines.append(_entities(result.get("techniques") or [], "Techniques").strip())
    lines.append(_entities(result.get("targets") or [], "Targets").strip())
    lines.append(_entities(result.get("indicators") or [], "Known indicators").strip())
    for report in (result.get("reports") or [])[:4]:
        lines.append(f"  · {report['source']}: {report['title'][:120]}")
    return "\n".join(line for line in lines if line)


async def _technique_context(technique: str) -> str:
    result = await cti.technique_context(technique)
    TOOL_CALLS.labels(tool="technique_context", outcome="ok").inc()
    if not result.get("known"):
        return f"No reporting citing {technique} in the local corpus."
    lines = [f"{result['technique']} — cited in the corpus."]
    if result.get("description"):
        lines.append(result["description"][:300])
    lines.append(_entities(result.get("actors") or [], "Used by").strip())
    lines.append(_entities(result.get("malware") or [], "Seen with malware").strip())
    for report in (result.get("reports") or [])[:4]:
        lines.append(f"  · {report['source']}: {report['title'][:120]}")
    return "\n".join(line for line in lines if line)


async def _campaign_check(days: int = 30) -> str:
    result = await cti.campaign_check(days=int(days or 30))
    TOOL_CALLS.labels(tool="campaign_check", outcome="ok").inc()
    trending = result.get("trending") or []
    if not trending:
        return (
            f"Nothing reported in the last {result.get('window_days')} days in the "
            "local corpus." + _corpus_note(result)
        )
    lines = [f"Most-reported in the last {result.get('window_days')} days:"]
    lines += [f"  · [{t['type']}] {t['name']} — {t['mentions']} report(s)" for t in trending]
    lines.append(
        "\nUse this to judge whether the current incident is an isolated event or "
        "part of something already being reported."
    )
    return "\n".join(lines)


def cti_tools() -> list[StructuredTool]:
    return [
        StructuredTool.from_function(
            coroutine=_check_indicator,
            name="check_indicator",
            description=(
                "Look up an IP, domain, URL, file hash or CVE in the local threat "
                "intelligence corpus. Returns whether any ingested source has reported it, "
                "who reported it, when it was first and last seen, and what threat actors "
                "or malware it is associated with. For a CVE it also reports whether the "
                "vulnerability is on a confirmed-exploitation catalogue. A 'not found' "
                "result means UNKNOWN, never clean. Args: indicator (the value to look up)."
            ),
        ),
        StructuredTool.from_function(
            coroutine=_actor_profile,
            name="actor_profile",
            description=(
                "Look up what the local corpus knows about a named threat actor or campaign "
                "— their tooling, techniques, targeted sectors and known indicators. Use "
                "when an alert or finding names a group. Args: actor (the group name)."
            ),
        ),
        StructuredTool.from_function(
            coroutine=_technique_context,
            name="technique_context",
            description=(
                "Look up a MITRE ATT&CK technique ID (e.g. T1567.002) in the local corpus "
                "to see which actors and malware are reported using it. "
                "Args: technique (the technique ID)."
            ),
        ),
        StructuredTool.from_function(
            coroutine=_campaign_check,
            name="campaign_check",
            description=(
                "List what the threat intelligence corpus has been reporting on recently. "
                "Use to judge whether this incident is isolated or part of a wider campaign. "
                "Args: days (lookback window, default 30)."
            ),
        ),
    ]
