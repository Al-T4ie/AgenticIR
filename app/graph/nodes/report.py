"""Final incident write-up."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from app.graph import llm, prompts
from app.graph.nodes.intake import now_iso
from app.graph.state import IncidentState
from app.observability import RUNS_COMPLETED, get_logger
from app.tools.builtin import alert_to_text

log = get_logger(__name__)


def _fallback_report(state: IncidentState) -> str:
    findings = state.get("findings", [])
    lines = [
        f"*Verdict:* {state.get('verdict', 'inconclusive')} "
        f"({state.get('severity', 'informational')} severity, "
        f"confidence {state.get('confidence', 0.0):.0%})",
        "",
        state.get("summary", "No summary available."),
        "",
        "*Findings*",
    ]
    lines += [
        f"• [{f.get('severity')}] {f.get('title')} — {f.get('detail', '')[:300]}" for f in findings
    ] or ["• None recorded."]
    if state.get("errors"):
        lines += ["", "*Errors during investigation*"]
        lines += [f"• {e}" for e in state["errors"][:10]]
    return "\n".join(lines)


async def report_node(state: IncidentState) -> dict[str, Any]:
    findings = state.get("findings", [])
    actions = state.get("containment_actions", [])
    executed = state.get("executed_actions", [])

    context = [
        f"INCIDENT: {state.get('incident_id')}",
        f"VERDICT: {state.get('verdict')} | SEVERITY: {state.get('severity')} | "
        f"CONFIDENCE: {state.get('confidence')}",
        "",
        "ORIGINAL ALERT:",
        alert_to_text(state.get("alert", {}))[:3000],
        "",
        "FINDINGS:",
        "\n".join(
            f"- [{f.get('specialist')}|{f.get('severity')}] {f.get('title')}: "
            f"{f.get('detail', '')[:400]}"
            + (
                f" (ATT&CK: {', '.join(f.get('mitre_techniques', []))})"
                if f.get("mitre_techniques")
                else ""
            )
            for f in findings
        )
        or "(none)",
        "",
        "PROPOSED ACTIONS:",
        "\n".join(
            f"- {a.get('action')} on {a.get('target')}: {a.get('justification')}" for a in actions
        )
        or "(none)",
        "",
        "EXECUTED ACTIONS:",
        "\n".join(f"- {a.get('action')} on {a.get('target')}" for a in executed) or "(none)",
    ]
    if state.get("errors"):
        context += ["", "ERRORS:", "\n".join(state["errors"][:10])]

    try:
        body = await llm.text(
            "supervisor",
            [SystemMessage(content=prompts.REPORT), HumanMessage(content="\n".join(context))],
        )
    except Exception as exc:
        log.error("report.failed", error=str(exc))
        body = _fallback_report(state)

    RUNS_COMPLETED.labels(
        status="completed", severity=str(state.get("severity", "informational"))
    ).inc()
    log.info("report.written", incident_id=state.get("incident_id"), chars=len(body))

    return {
        "report": body,
        "status": "completed",
        "timeline": [{"at": now_iso(), "actor": "reporter", "event": "Incident report generated"}],
    }
