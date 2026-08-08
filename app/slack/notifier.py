"""Outbound Slack messaging."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from slack_sdk.web.async_client import AsyncWebClient

from app.config import get_settings
from app.observability import get_logger
from app.services import incidents
from app.slack import blocks

log = get_logger(__name__)


@lru_cache(maxsize=1)
def get_client() -> AsyncWebClient:
    settings = get_settings()
    if not settings.slack_bot_token:
        raise RuntimeError("SLACK_ENABLED=true but SLACK_BOT_TOKEN is unset")
    return AsyncWebClient(token=settings.slack_bot_token)


async def post(
    channel: str,
    *,
    text: str,
    blocks_payload: list[dict[str, Any]] | None = None,
    thread_ts: str = "",
) -> str:
    """Post a message; returns its ts (empty string on failure)."""
    try:
        response = await get_client().chat_postMessage(
            channel=channel,
            text=text[:3000],  # fallback for notifications and screen readers
            blocks=blocks_payload,
            thread_ts=thread_ts or None,
            unfurl_links=False,
            unfurl_media=False,
        )
        return str(response.get("ts", ""))
    except Exception as exc:
        log.error("slack.post_failed", channel=channel, error=str(exc))
        return ""


async def notify_incident(incident_id: str, event: str, interrupt: Any = None) -> None:
    """Report a run transition into the incident's Slack thread."""
    settings = get_settings()
    record = await incidents.get_incident(incident_id)
    if record is None:
        return

    channel = record.get("slack_channel") or settings.slack_default_channel
    thread_ts = record.get("slack_thread_ts") or ""
    if not channel:
        return

    if event == "completed":
        await post(
            channel,
            text=f"Investigation complete: {record.get('verdict')} ({record.get('severity')})",
            blocks_payload=blocks.report_message(record, settings.public_base_url),
            thread_ts=thread_ts,
        )
    elif event == "awaiting_approval":
        payload = interrupt if isinstance(interrupt, dict) else {}
        await post(
            channel,
            text=f"Approval required for {incident_id}",
            blocks_payload=blocks.approval_request(incident_id, payload),
            thread_ts=thread_ts,
        )
    elif event == "failed":
        detail = "\n".join(record.get("errors", [])[-3:]) or "Unknown error"
        await post(
            channel,
            text=f"Investigation {incident_id} failed",
            blocks_payload=blocks.error_message(incident_id, detail),
            thread_ts=thread_ts,
        )


async def acknowledge(channel: str, thread_ts: str, incident_id: str, title: str) -> str:
    return await post(
        channel,
        text=f"Investigating {title} ({incident_id})",
        blocks_payload=blocks.acknowledgement(incident_id, title),
        thread_ts=thread_ts,
    )
