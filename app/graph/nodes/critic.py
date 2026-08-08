"""Adversarial reviewer: decides whether the investigation may close, and sets
the authoritative severity/verdict."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field

from app.config import SEVERITY_ORDER, get_settings
from app.graph import llm, prompts
from app.graph.nodes.intake import now_iso
from app.graph.state import IncidentState
from app.observability import concise_error, get_logger
from app.tools.builtin import alert_to_text

log = get_logger(__name__)


class Review(BaseModel):
    verdict: str = Field(description="true_positive | false_positive | inconclusive")
    severity: str = Field(description="informational | low | medium | high | critical")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    summary: str = Field(description="Two-sentence summary of what happened")
    needs_more_work: bool = Field(description="True only if a material gap remains")
    feedback: str = Field(
        default="", description="If needs_more_work: precisely what must be investigated next"
    )


def _highest_severity(findings: list[dict[str, Any]]) -> str:
    worst = "informational"
    for f in findings:
        sev = str(f.get("severity", "informational")).lower()
        if sev in SEVERITY_ORDER and SEVERITY_ORDER.index(sev) > SEVERITY_ORDER.index(worst):
            worst = sev
    return worst


async def critic_node(state: IncidentState) -> dict[str, Any]:
    settings = get_settings()
    findings = state.get("findings", [])
    current_round = int(state.get("round", 1))
    at_limit = current_round >= settings.max_investigation_rounds

    detail = (
        "\n".join(
            f"- [{f.get('specialist')}|{f.get('severity')}|conf={f.get('confidence')}] "
            f"{f.get('title')}: {f.get('detail', '')[:500]}"
            f"{' | evidence: ' + '; '.join(f.get('evidence', [])[:3]) if f.get('evidence') else ''}"
            for f in findings
        )
        or "(no findings were produced)"
    )

    context = [
        "ALERT:",
        alert_to_text(state.get("alert", {}))[:4000],
        "",
        f"INVESTIGATION ROUND {current_round} OF {settings.max_investigation_rounds}"
        + (" — this is the final round, no further work can be dispatched." if at_limit else ""),
        "",
        "FINDINGS:",
        detail,
    ]
    if state.get("errors"):
        context += ["", "SPECIALIST ERRORS:", "\n".join(state["errors"][-10:])]

    try:
        review = await llm.structured(
            "critic",
            Review,
            [SystemMessage(content=prompts.CRITIC), HumanMessage(content="\n".join(context))],
        )
    except Exception as exc:
        log.error("critic.failed", error=str(exc))
        worst = _highest_severity(findings)
        review = Review(
            verdict="inconclusive",
            severity=worst,
            confidence=0.3,
            summary=f"Automated review unavailable ({concise_error(exc)}). "
            f"{len(findings)} finding(s) recorded; "
            "manual analyst review required.",
            needs_more_work=False,
            feedback="",
        )

    severity = review.severity.lower()
    if severity not in SEVERITY_ORDER:
        severity = _highest_severity(findings)

    # The critic can ask for another round, but the round cap is ours to enforce.
    needs_more = bool(review.needs_more_work) and not at_limit

    log.info(
        "critic.reviewed",
        incident_id=state.get("incident_id"),
        verdict=review.verdict,
        severity=severity,
        needs_more_work=needs_more,
        round=current_round,
    )

    return {
        "verdict": review.verdict,
        "severity": severity,
        "confidence": review.confidence,
        "summary": review.summary,
        "needs_more_work": needs_more,
        "critic_feedback": review.feedback if needs_more else "",
        "timeline": [
            {
                "at": now_iso(),
                "actor": "critic",
                "event": (
                    f"Review: {review.verdict} at {severity} severity"
                    + (" — requesting another round" if needs_more else " — investigation closed")
                    + (" (round limit reached)" if at_limit and review.needs_more_work else "")
                ),
            }
        ],
    }
