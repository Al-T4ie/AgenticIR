"""Slack Events API, interactivity and slash-command endpoints.

Every route verifies the Slack signature against the raw body before parsing,
then returns within Slack's 3-second window while work continues in the
background.
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import parse_qs

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from app.observability import get_logger
from app.slack import handlers
from app.slack.verify import verify_slack_request

log = get_logger(__name__)

router = APIRouter(prefix="/slack", tags=["slack"])

_background: set[asyncio.Task] = set()


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


async def _verified_body(request: Request, timestamp: str | None, signature: str | None) -> bytes:
    body = await request.body()
    if not verify_slack_request(body, timestamp, signature):
        raise HTTPException(status_code=401, detail="Slack signature verification failed")
    return body


@router.post("/events", response_model=None)
async def slack_events(
    request: Request,
    x_slack_request_timestamp: str | None = Header(default=None),
    x_slack_signature: str | None = Header(default=None),
) -> JSONResponse | PlainTextResponse:
    body = await _verified_body(request, x_slack_request_timestamp, x_slack_signature)

    try:
        payload = json.loads(body)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed JSON") from None

    # One-time endpoint verification when the app is installed.
    if payload.get("type") == "url_verification":
        return PlainTextResponse(payload.get("challenge", ""))

    if not handlers.slack_enabled():
        log.warning("slack.event_dropped_disabled")
        return JSONResponse({"ok": True})

    # Slack retries on timeout; ack now, work later.
    _spawn(handlers.handle_event(payload))
    return JSONResponse({"ok": True})


@router.post("/interactions")
async def slack_interactions(
    request: Request,
    x_slack_request_timestamp: str | None = Header(default=None),
    x_slack_signature: str | None = Header(default=None),
) -> JSONResponse:
    body = await _verified_body(request, x_slack_request_timestamp, x_slack_signature)

    form = parse_qs(body.decode())
    raw = (form.get("payload") or [""])[0]
    if not raw:
        raise HTTPException(status_code=400, detail="Missing interaction payload")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed interaction payload") from None

    if not handlers.slack_enabled():
        return JSONResponse({"ok": True})

    _spawn(handlers.handle_interaction(payload))
    return JSONResponse({"ok": True})


@router.post("/commands")
async def slack_commands(
    request: Request,
    x_slack_request_timestamp: str | None = Header(default=None),
    x_slack_signature: str | None = Header(default=None),
) -> JSONResponse:
    body = await _verified_body(request, x_slack_request_timestamp, x_slack_signature)

    form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
    if not handlers.slack_enabled():
        return JSONResponse(
            {"response_type": "ephemeral", "text": "The IR bot is not enabled on this server."}
        )

    return JSONResponse(await handlers.handle_slash_command(form))
