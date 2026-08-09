"""Analyst dashboard.

Server-rendered so the whole surface is one container with no build step and no
external CDN — which also keeps it working behind Coolify's CSP-tight proxy.
Auth is the same API key, supplied once and kept in an HttpOnly cookie.
"""

from __future__ import annotations

import hmac
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Cookie, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from app.config import get_settings
from app.observability import get_logger
from app.services import (
    attack,
    incidents,
    ledger,
    runner,
    slackmd,
    stages,
    timeline,
    timings,
)

log = get_logger(__name__)

router = APIRouter(prefix="/ui", tags=["ui"])
templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))
# Reports are written in Slack markdown; the dashboard has to render it as HTML
# rather than show the asterisks. Escaping happens inside the filter.
templates.env.filters["slack_md"] = slackmd.to_html

_COOKIE = "agenticir_key"


def _authed(token: str | None) -> bool:
    settings = get_settings()
    return bool(token and settings.api_key and hmac.compare_digest(token, settings.api_key))


def _login_redirect() -> RedirectResponse:
    return RedirectResponse("/ui/login", status_code=303)


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, error: str = "") -> Any:
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/login")
async def login(api_key: str = Form(...)) -> Any:
    if not _authed(api_key):
        return RedirectResponse("/ui/login?error=Invalid+key", status_code=303)

    settings = get_settings()
    response = RedirectResponse("/ui", status_code=303)
    response.set_cookie(
        _COOKIE,
        api_key,
        httponly=True,
        samesite="lax",
        secure=settings.is_production,
        max_age=60 * 60 * 12,
    )
    return response


@router.post("/logout")
async def logout() -> Any:
    response = RedirectResponse("/ui/login", status_code=303)
    response.delete_cookie(_COOKIE)
    return response


@router.get("", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    status: str = "",
    severity: str = "",
    agenticir_key: str | None = Cookie(default=None),
) -> Any:
    if not _authed(agenticir_key):
        return _login_redirect()

    rows = await incidents.list_incidents(
        limit=100, status=status or None, severity=severity or None
    )
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {
            "incidents": rows,
            "counts": counts,
            "filter_status": status,
            "filter_severity": severity,
        },
    )


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_detail(
    request: Request, incident_id: str, agenticir_key: str | None = Cookie(default=None)
) -> Any:
    if not _authed(agenticir_key):
        return _login_redirect()

    record = await incidents.get_incident(incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown incident {incident_id}")

    pending = [a for a in record.get("containment_actions", []) if a.get("requires_approval")]
    try:
        chart = timeline.build(record.get("timeline", []))
    except Exception as exc:  # noqa: BLE001 — the page matters more than the picture
        log.warning("ui.timeline_chart_failed", incident_id=incident_id, error=str(exc))
        chart = {"empty": True, "lanes": [], "runs": [], "ticks": [], "total": 0.0}

    return templates.TemplateResponse(
        request,
        "incident.html",
        {
            "incident": record,
            "pending_actions": pending,
            "chart": chart,
            "pipeline": stages.derive(record),
            "specialist_states": stages.specialist_states(record),
            "specialists": stages.specialist_detail(record),
            "max_rounds": get_settings().max_investigation_rounds,
            "attack": attack.summarise(record.get("findings", [])),
            "can_approve": record["status"] == "awaiting_approval",
        },
    )


@router.get("/incidents/{incident_id}/report", response_class=HTMLResponse)
async def incident_report(
    request: Request, incident_id: str, agenticir_key: str | None = Cookie(default=None)
) -> Any:
    """The published report, with the record that backs it, on its own page.

    Separate from the incident view because it has a different reader: the
    incident page is for working an incident, this is what gets read afterwards,
    linked to, or printed for someone who was not in the channel.
    """
    if not _authed(agenticir_key):
        return _login_redirect()

    record = await incidents.get_incident(incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown incident {incident_id}")

    pipeline = stages.derive(record)
    # A reopened incident is re-assessed before it is re-reported, so the stored
    # report can describe a verdict the record has already moved past. Showing
    # it without saying so presents a superseded conclusion as the current one.
    reported = next(s["state"] for s in pipeline["steps"] if s["key"] == "report")

    # One incident measures TTR; MTTR needs a population. Pull a window of
    # recent incidents so the page can show this one against the mean rather
    # than presenting a single measurement as an average.
    try:
        recent = await incidents.list_incidents(limit=50, status="completed")
        fleet = timings.fleet([await incidents.get_incident(r["id"]) or {} for r in recent[:20]])
    except Exception as exc:  # noqa: BLE001 — the report matters more than the benchmark
        log.warning("ui.fleet_timings_failed", incident_id=incident_id, error=str(exc))
        fleet = {"count": 0, "phases": []}

    return templates.TemplateResponse(
        request,
        "report.html",
        {
            "incident": record,
            "attack": attack.summarise(record.get("findings", [])),
            "pipeline": pipeline,
            "timings": timings.measure(record),
            "fleet": fleet,
            "questions": timings.questions(record),
            "spend": ledger.summarise(record),
            "stale": bool(record.get("report")) and reported != "done",
        },
    )


@router.post("/incidents/{incident_id}/decide")
async def decide(
    incident_id: str,
    decision: str = Form(...),
    note: str = Form(default=""),
    agenticir_key: str | None = Cookie(default=None),
) -> Any:
    if not _authed(agenticir_key):
        return _login_redirect()

    record = await incidents.get_incident(incident_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Unknown incident {incident_id}")

    approved = decision == "approve"
    pending = [a for a in record.get("containment_actions", []) if a.get("requires_approval")]
    await runner.resume_investigation(
        incident_id,
        {
            "approved_all": approved,
            "approved_actions": [a["action"] for a in pending] if approved else [],
            "approver": "dashboard",
            "note": note or ("approved via dashboard" if approved else "rejected via dashboard"),
        },
    )
    return RedirectResponse(f"/ui/incidents/{incident_id}", status_code=303)


@router.post("/investigate")
async def start_from_ui(
    question: str = Form(...), agenticir_key: str | None = Cookie(default=None)
) -> Any:
    if not _authed(agenticir_key):
        return _login_redirect()
    if not question.strip():
        return RedirectResponse("/ui", status_code=303)

    record = await runner.start_investigation(
        question=question.strip(),
        alert={"title": question.strip()[:200], "raw": question.strip()},
        source="ui",
    )
    return RedirectResponse(f"/ui/incidents/{record['id']}", status_code=303)
