"""Built-in tools that need no external service.

These exist so the platform is useful before any n8n workflow is wired up, and
so tests have deterministic tools to exercise the graph with.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any

from langchain_core.tools import StructuredTool

from app.observability import TOOL_CALLS

# Deliberately conservative patterns — precision beats recall for IOC extraction,
# since every false hit costs an enrichment round-trip.
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|uk|de|fr|nl|br|in|dev|app)\b"
)
_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
_EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_indicators(text: str) -> dict[str, list[str]]:
    """Pull IOCs out of free text.

    Addresses are split on `is_global` rather than `is_private`: RFC 1918 space,
    loopback, link-local, CGNAT and the documentation ranges are all things an
    analyst must not chase as external infrastructure, and only `is_global`
    separates "worth enriching" from "internal or not routable" in one check.
    """
    public_ips: list[str] = []
    non_public_ips: list[str] = []
    for raw in set(_IPV4.findall(text)):
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            continue
        (public_ips if addr.is_global else non_public_ips).append(raw)

    hashes = sorted(set(_SHA256.findall(text)))
    # An MD5 pattern also matches the first 32 chars of nothing else here, but a
    # SHA-256 string contains no standalone 32-hex-char token, so no overlap check
    # is needed beyond excluding substrings of found sha256 values.
    md5s = [h for h in set(_MD5.findall(text)) if not any(h in s for s in hashes)]

    return {
        "public_ips": sorted(public_ips),
        "non_public_ips": sorted(non_public_ips),
        "domains": sorted(set(_DOMAIN.findall(text))),
        "sha256": hashes,
        "md5": sorted(md5s),
        "emails": sorted(set(_EMAIL.findall(text))),
        "cves": sorted({c.upper() for c in _CVE.findall(text)}),
    }


async def _extract_iocs_tool(text: str) -> str:
    TOOL_CALLS.labels(tool="extract_iocs", outcome="ok").inc()
    found = {k: v for k, v in extract_indicators(text).items() if v}
    if not found:
        return "No indicators found in the supplied text."
    return "\n".join(f"{k}: {', '.join(v)}" for k, v in found.items())


async def _classify_ip_tool(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        TOOL_CALLS.labels(tool="classify_ip", outcome="error").inc()
        return f"'{ip}' is not a valid IP address."
    TOOL_CALLS.labels(tool="classify_ip", outcome="ok").inc()
    facts = {
        "address": str(addr),
        "version": f"IPv{addr.version}",
        "private": addr.is_private,
        "loopback": addr.is_loopback,
        "link_local": addr.is_link_local,
        "multicast": addr.is_multicast,
        "reserved": addr.is_reserved,
        "globally_routable": addr.is_global,
    }
    return "\n".join(f"{k}: {v}" for k, v in facts.items())


def builtin_tools() -> list[StructuredTool]:
    return [
        StructuredTool.from_function(
            coroutine=_extract_iocs_tool,
            name="extract_iocs",
            description=(
                "Extract indicators of compromise (IPs, domains, file hashes, emails, CVEs) "
                "from a block of text such as a raw alert or log excerpt. "
                "Args: text (the text to scan)."
            ),
        ),
        StructuredTool.from_function(
            coroutine=_classify_ip_tool,
            name="classify_ip",
            description=(
                "Determine whether an IP address is private/internal, loopback, reserved, or "
                "globally routable. Use before treating an IP as an external threat. "
                "Args: ip (the address to classify)."
            ),
        ),
    ]


def alert_to_text(alert: dict[str, Any]) -> str:
    """Flatten an arbitrary alert dict into readable text for prompting."""
    lines: list[str] = []

    def walk(obj: Any, prefix: str = "") -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                walk(value, f"{prefix}{key}.")
        elif isinstance(obj, list):
            for i, value in enumerate(obj[:20]):
                walk(value, f"{prefix}{i}.")
        else:
            lines.append(f"{prefix.rstrip('.')}: {obj}")

    walk(alert)
    return "\n".join(lines[:400])
