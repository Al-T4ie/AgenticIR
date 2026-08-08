"""REST API: incidents, approvals, and inbound webhooks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import require_api_key, require_webhook_token
from app.observability import get_logger
from app.services import incidents, runner

log = get_logger(__name__)

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────
class StartInvestigation(BaseModel):
    alert: dict[str, Any] = Field(default_factory=dict, description="Raw alert payload")
    question: str = Field(default="", description="Optional analyst question")
    source: str = Field(default="api", description="api | n8n | webhook | slack")
    slack_channel: str = ""
    slack_thread_ts: str = ""


class ApprovalDecision(BaseModel):
    approved_all: bool = False
    approved_actions: list[str] = Field(default_factory=list)
    approver: str = "api"
    note: str = ""


class IncidentSummary(BaseModel):
    id: str
    status: str
    severity: str
    verdict: str
    title: str


# ── Incidents ────────────────────────────────────────────────────────────────
v1 = APIRouter(prefix="/v1", dependencies=[Depends(require_api_key)], tags=["incidents"])


@v1.post("/incidents", status_code=202, summary="Start an investigation")
async def create_investigation(payload: StartInvestigation) -> dict[str, Any]:
    if not payload.alert and not payload.question:
        raise HTTPException(status_code=422, detail="Provide at least one of `alert` or `question`")
    record = await runner.start_investigation(
        alert=payload.alert,
        question=payload.question,
        source=payload.source,
        slack_channel=payload.slack_channel,
        slack_thread_ts=payload.slack_thread_ts,
    )
    return {"incident_id": record["id"], "thread_id": record["thread_id"], "status": "running"}


@v1.get("/incidents", summary="List incidents")
async def list_investigations(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: str | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    rows = await incidents.list_incidents(
        limit=limit, offset=offset, status=status, severity=severity
    )
    return {"incidents": rows, "count": len(rows), "limit": limit, "offset": offset}


@v1.get("/incidents/{incident_id}", summary="Fetch one incident")
async def get_investigation(incident_id: str) -> dict[str, Any]:
    record = await incidents.get_incident(incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown incident {incident_id}")
    return record


@v1.get("/incidents/{incident_id}/state", summary="Raw graph state for an incident")
async def get_state(incident_id: str) -> dict[str, Any]:
    record = await incidents.get_incident(incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown incident {incident_id}")
    return await runner.get_thread_state(record["thread_id"])


@v1.post("/incidents/{incident_id}/approve", summary="Resolve a containment approval")
async def approve(incident_id: str, decision: ApprovalDecision) -> dict[str, Any]:
    record = await runner.resume_investigation(incident_id, decision.model_dump())
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown incident {incident_id}")
    return {"incident_id": incident_id, "status": "resuming"}


router.include_router(v1)


# ── Inbound webhooks ─────────────────────────────────────────────────────────
hooks = APIRouter(prefix="/webhooks", tags=["webhooks"])


@hooks.post(
    "/alert",
    status_code=202,
    dependencies=[Depends(require_webhook_token)],
    summary="Alert intake for n8n / SIEM / SOAR",
)
async def inbound_alert(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Accept an arbitrary alert body.

    Anything shaped `{"alert": {...}}` is unwrapped; anything else is treated as
    the alert itself, so SIEMs can post their native format without a transform.
    """
    alert = payload.get("alert") if isinstance(payload.get("alert"), dict) else payload
    question = str(payload.get("question", ""))
    source = str(payload.get("source", "webhook"))

    record = await runner.start_investigation(alert=alert, question=question, source=source)
    return {
        "incident_id": record["id"],
        "thread_id": record["thread_id"],
        "status": "accepted",
        "title": record["title"],
    }


router.include_router(hooks)
