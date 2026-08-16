"""REST API: incidents, approvals, and inbound webhooks."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import require_api_key, require_webhook_token
from app.config import get_settings
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


class FollowUp(BaseModel):
    note: str = Field(description="What has been learned since the last assessment")
    reported_by: str = Field(default="", description="Slack user id or analyst name")


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


@v1.post("/incidents/{incident_id}/follow-up", status_code=202, summary="Add information")
async def follow_up(incident_id: str, payload: FollowUp) -> dict[str, Any]:
    """Fold new information into an incident and re-assess it.

    The re-run continues the same graph thread, so prior findings are kept and
    the revised report lands in the original Slack thread. If the incident is
    mid-run or awaiting a containment decision it cannot be re-entered yet; the
    note is queued and applied the moment it goes idle. That is still an
    acceptance — a 409 here told callers their telemetry had been rejected when
    it had in fact been stored, which is the worst of both answers.
    """
    outcome = await runner.follow_up_investigation(
        incident_id, payload.note, reported_by=payload.reported_by
    )
    if outcome == "unknown":
        raise HTTPException(status_code=404, detail=f"Unknown incident {incident_id}")
    return {
        "incident_id": incident_id,
        "status": outcome,
        "applied": outcome == "revising",
    }


@v1.post("/slack/poll", summary="Run a Slack channel sweep now")
async def poll_now() -> dict[str, Any]:
    """Trigger the channel sweep out of band, rather than waiting for the timer."""
    from app.slack import poller

    return await poller.sweep()


@v1.get("/intel", summary="Threat intelligence corpus status")
async def intel_status() -> dict[str, Any]:
    """How much the corpus knows and whether its feeds are healthy.

    Worth an endpoint rather than a log line because the failure mode is silent:
    a corpus whose feeds have been 401ing for a week keeps answering every
    lookup with "not found", and "not found" is exactly what a working corpus
    says about a clean indicator. `stale` is the flag that separates them.
    """
    from app.services import cti, feeds

    settings = get_settings()
    if not settings.cti_enabled:
        return {"enabled": False, "corpus": {"reports": 0, "entities": 0}, "feeds": []}

    size = await cti.corpus_size()
    health = await cti.feed_health()
    configured = [
        {"name": f.name, "layer": f.layer, "description": f.description}
        for f in feeds.enabled_feeds()
    ]
    return {
        "enabled": True,
        "corpus": size,
        "feeds": health,
        "configured": configured,
        "failing": [f["name"] for f in health if f["consecutive_failures"] > 0],
        # An empty corpus cannot answer anything, and a lookup against it is
        # not evidence of a clean indicator.
        "stale": size["reports"] == 0 or not any(f["items_ingested"] for f in health),
    }


@v1.post("/intel/refresh", summary="Pull the threat intelligence feeds now")
async def intel_refresh() -> dict[str, Any]:
    """Run every enabled feed immediately instead of waiting for the caretaker."""
    from app.services import feeds

    if not get_settings().cti_enabled:
        raise HTTPException(status_code=400, detail="CTI_ENABLED is false")
    return await feeds.refresh()


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

    # An alert from a SIEM belongs in front of the analysts, not only in the
    # dashboard. Callers can override the destination; otherwise it goes to the
    # configured channel, and the run narrates itself in the thread it opens.
    settings = get_settings()
    channel = str(payload.get("slack_channel") or "")
    if not channel and settings.slack_enabled:
        channel = settings.slack_default_channel

    record = await runner.start_investigation(
        alert=alert, question=question, source=source, slack_channel=channel
    )
    return {
        "incident_id": record["id"],
        "thread_id": record["thread_id"],
        "status": "accepted",
        "title": record["title"],
    }


router.include_router(hooks)
