"""The specialist worker. One instance runs per dispatched task, in parallel.

Invoked via `Send`, so this node receives a purpose-built payload rather than the
full incident state. It returns only additive keys, which is what makes the
fan-out safe: concurrent specialists never contend for the same state slot.
"""

from __future__ import annotations

import time
from typing import Any, TypedDict

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from pydantic import BaseModel, Field, field_validator

from app.graph import llm, prompts
from app.graph.llm import coerce_json_list
from app.graph.nodes.intake import now_iso
from app.observability import ACTIVE_SPECIALISTS, NODE_DURATION, concise_error, get_logger
from app.slack import progress
from app.tools.builtin import builtin_tools
from app.tools.n8n import n8n_tools

log = get_logger(__name__)

MAX_TOOL_ITERATIONS = 4

_PROMPT_BY_SPECIALIST = {
    "triage": prompts.TRIAGE,
    "enrichment": prompts.ENRICHMENT,
    "behavioral": prompts.BEHAVIORAL,
}


class SpecialistPayload(TypedDict):
    """What `Send` hands to this node."""

    incident_id: str
    specialist: str
    objective: str
    alert_text: str
    prior_findings: str
    round: int


class ReportedFinding(BaseModel):
    title: str = Field(description="One-line summary of the finding")
    detail: str = Field(description="What was observed and what it means")
    severity: str = Field(
        default="informational",
        description="informational | low | medium | high | critical",
    )
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    iocs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list, description="e.g. T1059.001")
    evidence: list[str] = Field(
        default_factory=list, description="Specific observations backing this finding"
    )


class SpecialistReport(BaseModel):
    findings: list[ReportedFinding] = Field(
        default_factory=list, description="At most 4. Fewer is better. Empty is valid."
    )
    gaps: str = Field(default="", description="One line: what could not be determined")

    _coerce = field_validator("findings", mode="before")(coerce_json_list)


# One alert does not contain seven separate conclusions. Left uncapped, each
# round produced more findings than the last — 2 then 5 then 7 from the same
# specialist on the same alert — and the reviewer, whose job is to find claims
# the evidence does not support, correctly downgraded a true positive to
# inconclusive as the padding accumulated. More work made the verdict worse.
MAX_FINDINGS_PER_SPECIALIST = 4


def _best(findings: list[ReportedFinding]) -> list[ReportedFinding]:
    """Keep the findings that carry the most signal, drop the padding."""
    if len(findings) <= MAX_FINDINGS_PER_SPECIALIST:
        return findings
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
    ranked = sorted(
        findings,
        key=lambda f: (order.get(str(f.severity).lower(), 0), f.confidence),
        reverse=True,
    )
    return ranked[:MAX_FINDINGS_PER_SPECIALIST]


def _tools() -> list:
    return [*builtin_tools(), *n8n_tools()]


async def _run_tool_loop(system: str, task: str, incident_id: str) -> list:
    """Bounded ReAct loop. Returns the message history for the extraction step."""
    tools = _tools()
    messages: list = [SystemMessage(content=system), HumanMessage(content=task)]
    if not tools:
        return messages

    model = llm.get_llm("specialist").bind_tools(tools)
    by_name = {t.name: t for t in tools}

    for iteration in range(MAX_TOOL_ITERATIONS):
        try:
            reply: AIMessage = await model.ainvoke(messages)
        except Exception as exc:
            log.warning("specialist.tool_loop_llm_failed", error=str(exc), iteration=iteration)
            break

        messages.append(reply)
        calls = getattr(reply, "tool_calls", None) or []
        if not calls:
            break

        for call in calls:
            tool = by_name.get(call["name"])
            if tool is None:
                output = f"ERROR: unknown tool '{call['name']}'"
            else:
                args = dict(call.get("args") or {})
                if "incident_id" in getattr(tool, "args", {}) and not args.get("incident_id"):
                    args["incident_id"] = incident_id
                try:
                    output = str(await tool.ainvoke(args))
                except Exception as exc:
                    output = f"ERROR: tool raised {type(exc).__name__}: {exc}"
            messages.append(ToolMessage(content=output[:8000], tool_call_id=call["id"]))

    return messages


async def specialist_node(payload: SpecialistPayload) -> dict[str, Any]:
    name = payload["specialist"]
    system = _PROMPT_BY_SPECIALIST.get(name, prompts.TRIAGE)
    task = "\n".join(
        [
            f"OBJECTIVE: {payload['objective']}",
            "",
            "ALERT:",
            payload["alert_text"][:6000],
            "",
            "FINDINGS FROM OTHER SPECIALISTS SO FAR:",
            payload["prior_findings"][:4000],
        ]
    )

    incident_id = payload["incident_id"]
    await progress.specialist_started(incident_id, name, payload["objective"])
    started = time.monotonic()

    with NODE_DURATION.labels(node=f"specialist:{name}").time():
        ACTIVE_SPECIALISTS.labels(specialist=name).inc()
        try:
            history = await _run_tool_loop(system, task, incident_id)
            history.append(
                HumanMessage(
                    content=(
                        "Now report your findings as structured data. Include only conclusions "
                        "your investigation actually supports. If you found nothing of note, "
                        "return an empty findings list and explain why in `gaps`."
                    )
                )
            )
            report = await llm.structured("specialist", SpecialistReport, history)
        except Exception as exc:
            log.error("specialist.failed", specialist=name, error=str(exc))
            await progress.specialist_failed(incident_id, name, concise_error(exc))
            return {
                "errors": [f"{name}: {concise_error(exc)}"],
                "timeline": [
                    {
                        "at": now_iso(),
                        "actor": name,
                        "event": f"Specialist failed: {concise_error(exc)}",
                    }
                ],
            }
        finally:
            ACTIVE_SPECIALISTS.labels(specialist=name).dec()

    kept = _best(report.findings)
    if len(kept) < len(report.findings):
        log.info(
            "specialist.findings_capped",
            specialist=name,
            reported=len(report.findings),
            kept=len(kept),
        )
    findings = [
        {
            "specialist": name,
            "round": payload["round"],
            **f.model_dump(),
        }
        for f in kept
    ]

    elapsed = time.monotonic() - started
    log.info(
        "specialist.completed",
        incident_id=incident_id,
        specialist=name,
        findings=len(findings),
        seconds=round(elapsed, 1),
    )
    await progress.specialist_finished(incident_id, name, len(findings), elapsed, report.gaps)

    return {
        "findings": findings,
        "timeline": [
            {
                "at": now_iso(),
                "actor": name,
                "event": f"Reported {len(findings)} finding(s)"
                + (f"; gaps: {report.gaps[:200]}" if report.gaps else ""),
            }
        ],
    }
