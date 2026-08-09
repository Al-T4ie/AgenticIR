"""Shared incident state carried through the graph.

Reducer choice matters here: `findings`, `errors` and `timeline` use additive
reducers so parallel specialists can write concurrently without clobbering each
other. Scalar fields are last-write-wins and are only set by single-writer nodes
(supervisor, critic, report) to keep that safe.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

SpecialistName = Literal[
    "triage",
    "enrichment",
    "behavioral",
    "containment_planner",
    "report",
]

ALL_SPECIALISTS: list[str] = ["triage", "enrichment", "behavioral"]


class Finding(BaseModel):
    """One atomic conclusion produced by a specialist."""

    specialist: str
    title: str
    detail: str
    severity: str = "informational"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    iocs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    round: int = 0


class Task(BaseModel):
    """A unit of work the supervisor hands to a specialist."""

    specialist: str
    objective: str
    rationale: str = ""


class ContainmentAction(BaseModel):
    action: str
    target: str
    justification: str
    reversible: bool = True
    risk: str = "medium"
    requires_approval: bool = True
    tool: str = ""
    tool_args: dict[str, Any] = Field(default_factory=dict)


class TimelineEntry(BaseModel):
    at: str
    actor: str
    event: str


class IncidentState(TypedDict, total=False):
    # ── Identity ──
    incident_id: str
    thread_id: str
    source: str  # slack | n8n | api | webhook
    slack_channel: str
    slack_thread_ts: str

    # ── Input ──
    alert: dict[str, Any]
    question: str

    # ── Conversation ──
    messages: Annotated[list[AnyMessage], add_messages]

    # ── Planning / results ──
    plan: list[dict[str, Any]]
    findings: Annotated[list[dict[str, Any]], operator.add]
    timeline: Annotated[list[dict[str, Any]], operator.add]
    errors: Annotated[list[str], operator.add]

    # ── Verdict ──
    severity: str
    verdict: str  # true_positive | false_positive | inconclusive
    confidence: float
    summary: str

    # What the agents could not determine and a human could. Carried on the
    # incident so it can be asked once, tracked, and re-asked while unanswered.
    open_questions: list[str]

    # ── Response ──
    containment_actions: list[dict[str, Any]]
    approval: dict[str, Any]
    executed_actions: Annotated[list[dict[str, Any]], operator.add]
    report: str

    # ── Control ──
    round: int
    needs_more_work: bool
    critic_feedback: str
    status: str  # running | awaiting_approval | completed | failed
    # Bumped each time new information reopens a closed incident, so the thread
    # can say "revision 2" rather than silently replacing the first assessment.
    revision: int


def new_state(
    *,
    incident_id: str,
    thread_id: str,
    source: str,
    alert: dict[str, Any] | None = None,
    question: str = "",
    slack_channel: str = "",
    slack_thread_ts: str = "",
) -> IncidentState:
    return IncidentState(
        incident_id=incident_id,
        thread_id=thread_id,
        source=source,
        slack_channel=slack_channel,
        slack_thread_ts=slack_thread_ts,
        alert=alert or {},
        question=question,
        messages=[],
        plan=[],
        findings=[],
        timeline=[],
        errors=[],
        severity="informational",
        verdict="inconclusive",
        confidence=0.0,
        summary="",
        open_questions=[],
        containment_actions=[],
        approval={},
        executed_actions=[],
        report="",
        round=0,
        needs_more_work=True,
        critic_feedback="",
        status="running",
        revision=0,
    )
