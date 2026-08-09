"""Give an incident its own channel.

A thread in a shared channel is the right home for a routine alert. It is the
wrong home for something people are going to work for an hour: the conversation
is invisible unless you have the thread open, you cannot pull someone in without
losing them in the parent channel, and there is nowhere for the bot to keep a
running picture that is not buried under replies.

So when a human calls the bot in, the incident gets a room. Everything the bot
knows goes there, everything anyone asks goes there, and the room is the audit
record afterwards.

Failure here is never fatal. If the workspace has not granted the scope, or the
name collides, or Slack is having a day, the incident falls back to a thread —
an un-roomed investigation still beats a silent one.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from app.config import get_settings
from app.observability import get_logger
from app.slack.notifier import get_client

log = get_logger(__name__)

# Slack: lowercase, no spaces or periods, 80 chars. Being stricter than that
# because a channel name with punctuation in it is a name nobody can type.
_UNSAFE = re.compile(r"[^a-z0-9-]+")
_SQUEEZE = re.compile(r"-{2,}")
_MAX_NAME = 80

# Words that eat the character budget without telling anyone anything.
_NOISE = {
    "the", "a", "an", "and", "or", "of", "for", "from", "with", "on", "in", "to",
    "by", "at", "is", "was", "detected", "alert", "possible", "suspected",
    "unrecognised", "unrecognized", "performing",
}  # fmt: skip


def channel_name(incident_id: str, title: str) -> str:
    """`inc-20260809-bulk-crm-export-b90078c3`.

    Date first so channels sort chronologically in the sidebar, a readable slug
    in the middle so someone scanning the list knows what it was, and the short
    id last so two incidents on the same day about the same thing do not
    collide — which they will, because that is what a campaign looks like.
    """
    settings = get_settings()
    prefix = _UNSAFE.sub("-", settings.slack_warroom_prefix.lower()) or "inc"

    # INC-20260809-b90078c3 -> ("20260809", "b90078c3")
    parts = incident_id.split("-")
    date = (
        parts[1] if len(parts) > 2 and parts[1].isdigit() else datetime.now(UTC).strftime("%Y%m%d")
    )
    short = parts[-1][:8] if len(parts) > 2 else incident_id[-8:]

    words = [w for w in _UNSAFE.sub("-", title.lower()).split("-") if w and w not in _NOISE]
    slug = "-".join(words[:5])

    name = _SQUEEZE.sub("-", f"{prefix}-{date}-{slug}-{short}").strip("-")
    if len(name) <= _MAX_NAME:
        return name
    # Trim the slug rather than the id — the id is what makes it unique.
    keep = _MAX_NAME - len(f"{prefix}-{date}--{short}")
    return _SQUEEZE.sub("-", f"{prefix}-{date}-{slug[: max(keep, 0)].rstrip('-')}-{short}").strip(
        "-"
    )


async def open_room(
    incident_id: str,
    title: str,
    *,
    invite: list[str] | None = None,
    purpose: str = "",
) -> tuple[str, str]:
    """Create the incident's channel. Returns (channel_id, channel_name).

    Returns ("", "") on any failure, which the caller reads as "fall back to a
    thread". Never raises.
    """
    settings = get_settings()
    if not (settings.slack_enabled and settings.slack_warroom_enabled):
        return "", ""

    name = channel_name(incident_id, title)
    client = get_client()

    try:
        response = await client.conversations_create(
            name=name, is_private=settings.slack_warroom_private
        )
        channel = str(response["channel"]["id"])
    except Exception as exc:  # noqa: BLE001
        detail = str(exc)
        if "name_taken" in detail:
            # Almost certainly this incident's own room from an earlier attempt.
            found = await find_room(name)
            if found:
                log.info("warroom.reused", incident_id=incident_id, channel=found)
                return found, name
        # missing_scope is the one an operator has to fix, so name it plainly
        # rather than letting it read as a transient Slack error.
        log.error(
            "warroom.create_failed",
            incident_id=incident_id,
            name=name,
            error=detail,
            hint=(
                "grant groups:write (private) or channels:manage (public) and reinstall"
                if "missing_scope" in detail
                else ""
            ),
        )
        return "", ""

    log.info("warroom.created", incident_id=incident_id, channel=channel, name=name)

    # Topic and purpose are the only context a late arrival gets before
    # scrolling, so spend them on what the incident is, not on branding. Both
    # are cosmetic — never fail the room over them.
    try:
        await client.conversations_setPurpose(channel=channel, purpose=(purpose or title)[:250])
    except Exception as exc:  # noqa: BLE001
        log.warning("warroom.purpose_failed", channel=channel, error=str(exc))
    try:
        await client.conversations_setTopic(channel=channel, topic=f"{incident_id} · {title}"[:250])
    except Exception as exc:  # noqa: BLE001
        log.warning("warroom.topic_failed", channel=channel, error=str(exc))

    people = list(dict.fromkeys([*(invite or []), *_standing_invites()]))
    if people:
        try:
            await client.conversations_invite(channel=channel, users=",".join(people))
        except Exception as exc:  # noqa: BLE001
            # already_in_channel and cannot_invite_self are both fine.
            log.warning("warroom.invite_failed", channel=channel, users=len(people), error=str(exc))

    return channel, name


async def find_room(name: str) -> str:
    """Look up a channel the bot can see by name. Empty string if not found."""
    client = get_client()
    cursor = ""
    for _ in range(10):  # 10 * 200 channels is far past any sane workspace
        try:
            response = await client.conversations_list(
                types="public_channel,private_channel", limit=200, cursor=cursor or None
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("warroom.list_failed", error=str(exc))
            return ""
        for channel in response.get("channels", []):
            if channel.get("name") == name:
                return str(channel.get("id", ""))
        cursor = str((response.get("response_metadata") or {}).get("next_cursor") or "")
        if not cursor:
            break
    return ""


def _standing_invites() -> list[str]:
    raw = get_settings().slack_warroom_invite
    return [u.strip() for u in raw.split(",") if u.strip()]


async def announce(origin_channel: str, thread_ts: str, channel_id: str, incident_id: str) -> None:
    """Point the people who asked at where the work moved to."""
    settings = get_settings()
    if not (settings.slack_warroom_announce and origin_channel and channel_id):
        return
    from app.slack import notifier

    await notifier.post(
        origin_channel,
        text=f"Opened <#{channel_id}> for `{incident_id}` — working it there.",
        thread_ts=thread_ts or "",
    )


async def archive(channel_id: str, incident_id: str) -> bool:
    """Close the room. Slack keeps archived channels readable, so nothing is lost."""
    if not channel_id:
        return False
    try:
        await get_client().conversations_archive(channel=channel_id)
        log.info("warroom.archived", incident_id=incident_id, channel=channel_id)
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("warroom.archive_failed", channel=channel_id, error=str(exc))
        return False


def opening_brief(
    record: dict[str, Any], mode_blurb: str, unlock_seconds: int
) -> list[dict[str, Any]]:
    """The first message in the room: what happened, and what the bot will do.

    Written for someone who has just been added and knows nothing — the alert in
    one line, then explicitly what posture the bot is in, because a bot that
    silently does nothing and a bot that is about to act look identical until
    one of them acts.
    """
    alert = record.get("alert") or {}
    facts = [
        f"*Source* {record.get('source', 'unknown')}",
        f"*Severity* {record.get('severity', 'unknown')}",
    ]
    for key in ("host", "user", "src_ip", "platform", "source_product", "source_system"):
        if alert.get(key):
            facts.append(f"*{key.replace('_', ' ').title()}* {alert[key]}")

    detail = str(alert.get("detail") or alert.get("summary") or record.get("summary") or "")
    minutes = max(1, round(unlock_seconds / 60))

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": str(record.get("title", "Incident"))[:150]},
        },
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": f"`{record.get('id')}`  ·  " + "  ·  ".join(facts)}
            ],
        },
        *(
            [{"type": "section", "text": {"type": "mrkdwn", "text": detail[:2800]}}]
            if detail
            else []
        ),
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f":eyes: *Spectator* — {mode_blurb}\n"
                    f"Ask me anything here and only you see the answer. "
                    f"In {minutes} min you can hand me more: "
                    "`@IR mode winger` to have me investigate and propose, "
                    "`@IR mode responder` to have me act."
                ),
            },
        },
    ]
