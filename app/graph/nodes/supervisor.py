"""The orchestrator: decides which specialists to run this round."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import BaseModel, Field, field_validator

from app.config import get_settings
from app.graph import llm, prompts
from app.graph.llm import coerce_json_list
from app.graph.nodes.intake import now_iso
from app.graph.state import ALL_SPECIALISTS, IncidentState
from app.observability import get_logger
from app.slack import progress
from app.tools.builtin import alert_to_text

log = get_logger(__name__)


class PlannedTask(BaseModel):
    specialist: str = Field(description=f"One of: {', '.join(ALL_SPECIALISTS)}")
    objective: str = Field(description="Concrete question this specialist must answer")
    rationale: str = Field(default="", description="Why this is worth doing now")


class Plan(BaseModel):
    reasoning: str = Field(description="Brief justification for the dispatch decision")
    tasks: list[PlannedTask] = Field(
        default_factory=list, description="Specialists to run in parallel. Empty means done."
    )

    _coerce = field_validator("tasks", mode="before")(coerce_json_list)


def _findings_digest(findings: list[dict[str, Any]], limit: int = 40) -> str:
    if not findings:
        return "(nothing gathered yet)"
    lines = []
    for f in findings[-limit:]:
        lines.append(
            f"- [{f.get('specialist')}|{f.get('severity')}|conf={f.get('confidence')}] "
            f"{f.get('title')}: {f.get('detail', '')[:400]}"
        )
    return "\n".join(lines)


def _merge_duplicates(tasks: list[PlannedTask]) -> list[PlannedTask]:
    """Fold repeats of one specialist in a single round into one task.

    Observed in production: the supervisor dispatched `behavioral` three times in
    the same round. Each copy gets the same prompt and the same alert, so they
    largely duplicate each other's work — three agents' cost and eleven
    near-identical findings for the reviewer to wade through. Merging the
    objectives keeps every question that was asked while running the specialist
    once, which is strictly better than dropping the extras.
    """
    merged: dict[str, PlannedTask] = {}
    for task in tasks:
        seen = merged.get(task.specialist)
        if seen is None:
            merged[task.specialist] = task
            continue
        if task.objective.strip() and task.objective.strip() not in seen.objective:
            seen.objective = f"{seen.objective}\nAlso: {task.objective.strip()}"
    return list(merged.values())


async def supervisor_node(state: IncidentState) -> dict[str, Any]:
    settings = get_settings()
    current_round = int(state.get("round", 0)) + 1
    findings = state.get("findings", [])

    context = [
        f"Incident ID: {state.get('incident_id')}",
        f"Round: {current_round} of max {settings.max_investigation_rounds}",
        "",
        "ALERT:",
        alert_to_text(state.get("alert", {}))[:6000],
    ]
    if state.get("question"):
        context += ["", f"ANALYST QUESTION: {state['question']}"]
    if findings:
        context += ["", "FINDINGS SO FAR:", _findings_digest(findings)]
    if state.get("critic_feedback"):
        context += ["", "REVIEWER FEEDBACK TO ADDRESS:", state["critic_feedback"]]

    try:
        plan = await llm.structured(
            "supervisor",
            Plan,
            [SystemMessage(content=prompts.SUPERVISOR), HumanMessage(content="\n".join(context))],
        )
    except Exception as exc:
        # A dead supervisor shouldn't kill the incident — fall back to a sane
        # default sweep on round 1, and stop planning after that.
        log.error("supervisor.failed", error=str(exc), round=current_round)
        fallback = (
            [
                PlannedTask(specialist=s, objective="Standard investigation of this alert")
                for s in ALL_SPECIALISTS
            ]
            if current_round == 1
            else []
        )
        plan = Plan(
            reasoning=f"Supervisor LLM failed ({exc}); using fallback plan.", tasks=fallback
        )

    known = [t for t in plan.tasks if t.specialist in ALL_SPECIALISTS]
    valid = _merge_duplicates(known)[: settings.max_parallel_specialists]
    dropped = len(plan.tasks) - len(valid)
    if dropped > 0:
        log.warning("supervisor.tasks_dropped", count=dropped, round=current_round)

    log.info(
        "supervisor.planned",
        incident_id=state.get("incident_id"),
        round=current_round,
        specialists=[t.specialist for t in valid],
    )
    await progress.planning(
        str(state.get("incident_id", "")),
        current_round,
        [t.specialist for t in valid],
        plan.reasoning,
    )

    return {
        "round": current_round,
        "plan": [t.model_dump() for t in valid],
        "critic_feedback": "",  # consumed
        "timeline": [
            {
                "at": now_iso(),
                "actor": "supervisor",
                "event": (
                    f"Round {current_round}: dispatched {', '.join(t.specialist for t in valid)}"
                    if valid
                    else f"Round {current_round}: no further investigation needed"
                ),
            }
        ],
    }
