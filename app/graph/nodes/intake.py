"""Normalise whatever arrived (SIEM JSON, Slack text, n8n payload) into state."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.graph.state import IncidentState
from app.observability import get_logger
from app.tools.builtin import alert_to_text, extract_indicators

log = get_logger(__name__)


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


async def intake_node(state: IncidentState) -> dict[str, Any]:
    alert = state.get("alert", {}) or {}
    question = state.get("question", "")

    corpus = "\n".join([alert_to_text(alert), question])
    indicators = {k: v for k, v in extract_indicators(corpus).items() if v}

    # A provisional severity from the source system, if it gave us one. The
    # triage specialist may override this; we only use it to seed the record.
    raw_sev = str(alert.get("severity", alert.get("priority", ""))).lower()
    seed_sev = (
        raw_sev
        if raw_sev in {"informational", "low", "medium", "high", "critical"}
        else "informational"
    )

    log.info(
        "intake.normalised",
        incident_id=state.get("incident_id"),
        source=state.get("source"),
        indicator_kinds=list(indicators),
    )

    return {
        "alert": {**alert, "_indicators": indicators, "_text": corpus[:20000]},
        "severity": seed_sev,
        "status": "running",
        "round": 0,
        "timeline": [
            {
                "at": now_iso(),
                "actor": "intake",
                "event": f"Incident opened from {state.get('source', 'unknown')} source"
                + (
                    f" with {sum(len(v) for v in indicators.values())} indicators"
                    if indicators
                    else ""
                ),
            }
        ],
    }
