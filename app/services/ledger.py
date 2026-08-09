"""What each agent spent: tokens, tools, and time.

The Prometheus counters answer "how much did the service do today". They cannot
answer "what did *this* incident cost, and which agent spent it", because they
carry no incident label — and adding one would blow up cardinality for a
question better answered from the record anyway.

So every model call and every tool call is written to the incident it belongs
to. That makes three things possible that were not: showing a responder which
agents actually ran inside each phase of the response, attributing spend to the
specialist that caused it, and auditing which external systems an investigation
touched — the last of which is the question a security team will eventually be
asked about a tool that can reach into production.

Attribution rides on context variables rather than threaded parameters. The
alternative is passing an incident id through every model helper and every tool
signature, and a tool that takes an audit parameter is a tool a model can lie
to.
"""

from __future__ import annotations

import contextvars
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from app.observability import get_logger

log = get_logger(__name__)

_incident: contextvars.ContextVar[str] = contextvars.ContextVar("ledger_incident", default="")
_actor: contextvars.ContextVar[str] = contextvars.ContextVar("ledger_actor", default="")

# Written synchronously would mean a database round trip inside every model
# call. Entries accumulate here and are flushed when the node finishes, which
# is also when the incident row is next written anyway.
_pending: dict[str, list[dict[str, Any]]] = {}


@contextmanager
def bind(incident_id: str = "", actor: str = "") -> Iterator[None]:
    """Attribute everything recorded inside this block."""
    tokens = []
    if incident_id:
        tokens.append((_incident, _incident.set(incident_id)))
    if actor:
        tokens.append((_actor, _actor.set(actor)))
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


def current() -> tuple[str, str]:
    return _incident.get(), _actor.get()


def record_llm(
    *,
    role: str,
    model: str = "",
    input_tokens: int = 0,
    output_tokens: int = 0,
    duration_ms: int = 0,
    outcome: str = "ok",
) -> None:
    """One model call. Zero tokens is normal — not every provider reports usage."""
    incident_id, actor = current()
    if not incident_id:
        return
    _pending.setdefault(incident_id, []).append(
        {
            "at": datetime.now(UTC).isoformat(),
            "kind": "llm",
            "actor": actor or role,
            "role": role,
            "model": model,
            "input_tokens": int(input_tokens or 0),
            "output_tokens": int(output_tokens or 0),
            "duration_ms": int(duration_ms or 0),
            "outcome": outcome,
        }
    )


def record_tool(*, tool: str, outcome: str = "ok", target: str = "", duration_ms: int = 0) -> None:
    """One tool call. `target` is the audit answer to 'what did it touch'."""
    incident_id, actor = current()
    if not incident_id:
        return
    _pending.setdefault(incident_id, []).append(
        {
            "at": datetime.now(UTC).isoformat(),
            "kind": "tool",
            "actor": actor,
            "tool": tool,
            "target": str(target)[:200],
            "duration_ms": int(duration_ms or 0),
            "outcome": outcome,
        }
    )


@contextmanager
def timed() -> Iterator[dict[str, int]]:
    """Measure a call without making every caller do the arithmetic."""
    started = time.monotonic()
    box = {"ms": 0}
    try:
        yield box
    finally:
        box["ms"] = int((time.monotonic() - started) * 1000)


def take(incident_id: str) -> list[dict[str, Any]]:
    """Hand over everything buffered for one incident and clear it."""
    return _pending.pop(incident_id, [])


async def flush(incident_id: str) -> int:
    """Append the buffer to the incident row. Never raises — this is bookkeeping.

    Losing a usage entry must never lose an investigation, so a failure here is
    logged and swallowed rather than propagated into the node that spent it.
    """
    entries = take(incident_id)
    if not entries:
        return 0
    try:
        from app.services import incidents

        await incidents.append_usage(incident_id, entries)
    except Exception as exc:  # noqa: BLE001
        log.warning("ledger.flush_failed", incident_id=incident_id, error=str(exc))
        return 0
    return len(entries)


# ── Reading it back ──────────────────────────────────────────────────────────
def summarise(record: dict[str, Any]) -> dict[str, Any]:
    """Per-agent totals for the report, plus the systems that were touched."""
    usage = record.get("usage") or []
    agents: dict[str, dict[str, Any]] = {}
    tools: dict[str, dict[str, Any]] = {}

    for item in usage:
        actor = str(item.get("actor") or item.get("role") or "unknown")
        row = agents.setdefault(
            actor,
            {
                "actor": actor,
                "calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "tokens": 0,
                "tool_calls": 0,
                "ms": 0,
                "models": set(),
                "failures": 0,
            },
        )
        row["ms"] += int(item.get("duration_ms") or 0)
        if item.get("outcome") not in (None, "", "ok"):
            row["failures"] += 1

        if item.get("kind") == "llm":
            row["calls"] += 1
            row["input_tokens"] += int(item.get("input_tokens") or 0)
            row["output_tokens"] += int(item.get("output_tokens") or 0)
            if item.get("model"):
                row["models"].add(str(item["model"]))
        else:
            row["tool_calls"] += 1
            name = str(item.get("tool") or "unknown")
            t = tools.setdefault(
                name, {"tool": name, "calls": 0, "failures": 0, "targets": set(), "by": set()}
            )
            t["calls"] += 1
            if item.get("outcome") not in (None, "", "ok"):
                t["failures"] += 1
            if item.get("target"):
                t["targets"].add(str(item["target"]))
            if actor:
                t["by"].add(actor)

    for row in agents.values():
        row["tokens"] = row["input_tokens"] + row["output_tokens"]
        row["models"] = sorted(row["models"])

    ordered = sorted(agents.values(), key=lambda r: r["tokens"], reverse=True)
    peak = max((r["tokens"] for r in ordered), default=0)
    total = sum(r["tokens"] for r in ordered)
    for row in ordered:
        # Width for the bar. Relative to the biggest spender, not to the total,
        # so the shape stays readable when one agent dominates.
        row["share"] = round(row["tokens"] / peak * 100) if peak else 0
        row["pct"] = round(row["tokens"] / total * 100) if total else 0

    tool_rows = sorted(tools.values(), key=lambda t: t["calls"], reverse=True)
    for t in tool_rows:
        t["targets"] = sorted(t["targets"])[:6]
        t["by"] = sorted(t["by"])

    return {
        "agents": ordered,
        "tools": tool_rows,
        "total_tokens": total,
        "input_tokens": sum(r["input_tokens"] for r in ordered),
        "output_tokens": sum(r["output_tokens"] for r in ordered),
        "llm_calls": sum(r["calls"] for r in ordered),
        "tool_calls": sum(r["tool_calls"] for r in ordered),
        # Zero tokens with calls recorded means the provider withheld usage —
        # worth saying rather than rendering an empty chart.
        "tokens_unreported": total == 0 and any(r["calls"] for r in ordered),
        "empty": not usage,
    }
