"""Slack event and interactivity handling.

Slack retries anything it doesn't get a 200 for within 3 seconds, so every
handler here acknowledges immediately and does the real work in the background.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from app.config import get_settings
from app.observability import get_logger
from app.services import incidents, runner, slack_watch
from app.slack import blocks, notifier

log = get_logger(__name__)

# Drop the leading <@U123456> mention from the analyst's text.
_MENTION = re.compile(r"<@[A-Z0-9]+>\s*")
# Slack wraps bare URLs/emails as <url|label>; keep the label.
_SLACK_LINK = re.compile(r"<(?:https?://|mailto:)([^|>]+)(?:\|[^>]*)?>")

_background: set[asyncio.Task] = set()


def _spawn(coro) -> None:
    task = asyncio.create_task(coro)
    _background.add(task)
    task.add_done_callback(_background.discard)


def clean_text(raw: str) -> str:
    text = _MENTION.sub("", raw or "")
    text = _SLACK_LINK.sub(r"\1", text)
    return text.strip()


async def handle_event(payload: dict[str, Any]) -> None:
    """Route an Events API callback. Called after the HTTP 200 has been sent."""
    event = payload.get("event", {}) or {}
    kind = event.get("type")

    # Ignore our own messages and any bot chatter, or we loop forever.
    if event.get("bot_id") or event.get("subtype") == "bot_message":
        return

    is_mention = kind == "app_mention"
    is_dm = kind == "message" and event.get("channel_type") == "im"

    if not (is_mention or is_dm):
        log.debug("slack.event_ignored", kind=kind)
        return

    # Claim the message so the channel poller doesn't handle it a second time.
    # Slack also redelivers events on its own retry schedule; the claim makes
    # that idempotent too. A DM channel is never polled, so it needs no claim.
    channel = str(event.get("channel", ""))
    ts = str(event.get("ts", ""))
    if is_mention and channel and ts:
        try:
            if not await slack_watch.claim(channel, ts, disposition="mention"):
                log.info("slack.event_already_claimed", channel=channel, ts=ts)
                return
        except Exception as exc:  # noqa: BLE001 — never drop an event over bookkeeping
            log.warning("slack.claim_failed", error=str(exc))

    await _handle_mention(event)


async def _handle_mention(event: dict[str, Any]) -> None:
    channel = event.get("channel", "")
    user = event.get("user", "")
    text = clean_text(event.get("text", ""))
    # Reply in-thread when mentioned inside one; otherwise start a thread on this message.
    thread_ts = event.get("thread_ts") or event.get("ts", "")

    if not text:
        await notifier.post(
            channel,
            text="Tell me what to investigate.",
            thread_ts=thread_ts,
        )
        return

    # Inside an incident's own room, every mention is about that incident —
    # there is no thread to key off, the channel *is* the key. Skipped entirely
    # when rooms are off: there is nothing to find, and this runs on every
    # mention in every channel the bot is in.
    room_incident = (
        await incidents.get_by_slack_channel(channel)
        if get_settings().slack_warroom_enabled
        else None
    )

    # "mode winger" is a control instruction, not information about the
    # incident. Checked before anything else so it can never be mistaken for
    # telemetry and fed to the graph.
    if await _handle_mode_command(text, room_incident, channel, thread_ts, user):
        return

    # A mention inside an existing incident thread is a follow-up, not a new
    # incident.
    existing = await incidents.get_by_slack_thread(channel, thread_ts) or room_incident
    if existing:
        await _handle_followup(existing, text, channel, thread_ts, user=user)
        return

    # Not every mention is an alert. "@IR what did we conclude about FIN-WS-04?"
    # asked in the channel used to spin up a fresh multi-agent investigation of
    # the question itself; it should be answered from the incident it refers to.
    target = await _question_about_existing(channel, text, user)
    if target is not None:
        log.info("slack.answering_from_record", incident_id=target["id"], user=user)
        await answer_followup(target, text, channel, thread_ts)
        return

    record = await runner.start_investigation(
        question=text,
        alert={"title": text[:200], "reported_by": user, "channel": channel, "raw": text},
        source="slack",
        slack_channel=channel,
        slack_thread_ts=thread_ts,
    )
    await notifier.acknowledge(channel, thread_ts, record["id"], record["title"])
    log.info("slack.investigation_started", incident_id=record["id"], user=user)


_MODE_RE = re.compile(r"^\s*(?:mode|switch|go|set\s+mode)\b[:\s]*([a-z\-_ ]*)$", re.I)


async def _handle_mode_command(
    text: str, incident: dict[str, Any] | None, channel: str, thread_ts: str, user: str
) -> bool:
    """`@IR mode winger`. Returns True if this was a mode instruction.

    Deliberately narrow: only an exact `mode …` phrasing counts. Anything looser
    would let a sentence like "we should go autonomous on this" silently hand a
    machine permission to act, which is not a thing to infer from prose.
    """
    match = _MODE_RE.match(text)
    if not match:
        return False

    from app.services import modes

    settings = get_settings()
    asked = match.group(1).strip()

    if incident is None:
        await notifier.post(
            channel,
            text=f"Modes are per incident — ask me in an incident's channel. {modes.choices()}",
            thread_ts=thread_ts,
        )
        return True

    current = modes.get(incident.get("mode"))
    if not asked:
        await notifier.post(
            channel,
            text=f"Currently *{current.label}* — {current.blurb}\n{modes.choices()}",
            thread_ts=thread_ts,
        )
        return True

    target = modes.resolve(asked)
    if target is None:
        await notifier.post(
            channel,
            text=f"`{asked}` is not a mode. {modes.choices()}",
            thread_ts=thread_ts,
        )
        return True

    opened = incident.get("channel_opened_at")
    opened_at = _parse_ts(opened)
    # Dropping *down* the ladder is always allowed. The wait exists to stop
    # someone granting autonomy before they have read anything, not to trap
    # them in a posture they have decided against.
    widening = _rank(target.key) > _rank(current.key)
    if widening and not modes.unlocked(opened_at, after_seconds=settings.ir_mode_unlock_seconds):
        wait = modes.seconds_until_unlock(opened_at, after_seconds=settings.ir_mode_unlock_seconds)
        await notifier.post(
            channel,
            text=(
                f"Not yet — {wait // 60}m{wait % 60:02d}s before I can move up to "
                f"*{target.label}*. Read what I have first. You can drop to a lower "
                "mode at any time."
            ),
            thread_ts=thread_ts,
        )
        return True

    await incidents.set_mode(incident["id"], target.key, by=user)
    await incidents.append_timeline(
        incident["id"],
        {"actor": f"human:{user}", "event": f"Mode set to {target.label} ({target.key})"},
    )
    ceiling = (
        f" Acting unattended up to *{settings.ir_autonomous_max_risk}* risk; "
        "irreversible actions still come to you."
        if target.key == modes.RESPONDER
        else ""
    )
    await notifier.post(
        channel,
        text=f":gear: Mode → *{target.label}* (by <@{user}>). {target.blurb}{ceiling}",
        thread_ts=thread_ts,
    )
    log.info("slack.mode_set", incident_id=incident["id"], mode=target.key, user=user)
    return True


_LADDER = {"spectator": 0, "winger": 1, "responder": 2}


def _rank(key: str) -> int:
    return _LADDER.get(key, 0)


def _parse_ts(value: Any) -> Any:
    from datetime import datetime

    if not value:
        return None
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return None
    return value


async def _question_about_existing(channel: str, text: str, user: str) -> dict[str, Any] | None:
    """The incident this mention is asking about, or None to investigate afresh."""
    try:
        from app.slack import poller

        known = await poller._recent_incidents(channel)
        if not known:
            return None
        dispositions = await poller.classify(
            [{"ts": "mention", "user": user, "text": text, "thread_ts": "", "incident_id": ""}],
            known,
        )
    except Exception as exc:  # noqa: BLE001 — fall through to investigating
        log.warning("slack.mention_classification_failed", error=str(exc))
        return None

    decision = dispositions.get("mention")
    if decision is None or decision.action != "answer":
        return None
    return next((i for i in known if i["id"] == decision.incident_id), None)


async def _handle_followup(
    incident: dict[str, Any], text: str, channel: str, thread_ts: str, user: str = ""
) -> None:
    """Handle a mention inside an incident thread.

    Two things arrive here and they need different treatment: a *question* about
    the incident, which is answered from the record, and *new information*,
    which should reopen the investigation rather than be answered at.
    """
    status = incident.get("status")
    if status == "running":
        await notifier.post(
            channel,
            text="Still working on it — I'll post here when the investigation completes.",
            thread_ts=thread_ts,
        )
        return
    if status == "awaiting_approval":
        await notifier.post(
            channel,
            text="This incident is waiting on a containment decision — use the buttons above.",
            thread_ts=thread_ts,
        )
        return

    if await _adds_information(incident, text, user):
        outcome = await runner.follow_up_investigation(incident["id"], text, reported_by=user)
        if outcome == "revising":
            await notifier.post(
                channel,
                text="New information noted — re-assessing.",
                blocks_payload=[
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": ":arrows_counterclockwise: *New information* — "
                            f"re-assessing `{incident['id']}` with this taken into account.",
                        },
                    }
                ],
                thread_ts=thread_ts,
            )
            return
        # Anything else (a race back into running, a vanished record) is better
        # answered than silently dropped.

    await answer_followup(incident, text, channel, thread_ts)


async def _adds_information(incident: dict[str, Any], text: str, user: str) -> bool:
    """Does this message change what we know, or is it just asking?"""
    try:
        from app.slack import poller

        dispositions = await poller.classify(
            [
                {
                    "ts": "followup",
                    "user": user,
                    "text": text,
                    "thread_ts": incident.get("slack_thread_ts", ""),
                    "incident_id": incident["id"],
                }
            ],
            [incident],
        )
    except Exception as exc:  # noqa: BLE001 — fall back to answering, never to silence
        log.warning("slack.intent_classification_failed", error=str(exc))
        return False
    decision = dispositions.get("followup")
    return bool(decision and decision.action == "update_incident")


async def answer_followup(
    incident: dict[str, Any], text: str, channel: str, thread_ts: str
) -> None:
    """Answer a question strictly from what the incident record contains."""
    from langchain_core.messages import HumanMessage, SystemMessage

    from app.graph import llm

    # The whole record, not a slice of it. "Give me the timeline" is a fair
    # question that could not be answered while the timeline was the one field
    # left out — and the failure mode is a confident answer from the parts that
    # were supplied, rather than an admission that the data was missing.
    context = json.dumps(
        {
            "id": incident.get("id"),
            "status": incident.get("status"),
            "verdict": incident.get("verdict"),
            "severity": incident.get("severity"),
            "confidence": incident.get("confidence"),
            "summary": incident.get("summary"),
            "timeline": incident.get("timeline", [])[-40:],
            "findings": incident.get("findings", [])[:30],
            "containment_actions": incident.get("containment_actions", []),
            "executed_actions": incident.get("executed_actions", []),
            "open_questions": incident.get("open_questions", []),
            "errors": incident.get("errors", [])[-5:],
            "report": (incident.get("report") or "")[:6000],
        },
        default=str,
    )
    try:
        answer = await llm.text(
            "specialist",
            [
                SystemMessage(
                    content=(
                        "You are answering an analyst mid-incident, in Slack, about an "
                        "investigation that has already run. Answer only from the incident "
                        "record supplied.\n\n"
                        "At most three sentences — unless they asked for a timeline, a "
                        "sequence or a list, in which case give exactly that as compact "
                        "bullets, newest last, one line each.\n\n"
                        "No preamble, no restating the question, no summary of the incident "
                        "they already have. If the record does not contain the answer, say "
                        "so in one line and name the one thing that would settle it. Never "
                        "infer events that are not in the record. Slack markdown."
                    )
                ),
                HumanMessage(content=f"INCIDENT RECORD:\n{context}\n\nASKED: {text}"),
            ],
        )
    except Exception as exc:
        log.error("slack.followup_failed", error=str(exc))
        answer = f"Couldn't answer that: {exc}"

    # Show the question that was picked up alongside the answer. When the bot
    # answers something nobody asked — the wrong message, or the wrong reading
    # of the right one — that is only visible if the question is on the record
    # next to the answer.
    await notifier.post(
        channel,
        text=answer,
        blocks_payload=[
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f":speech_balloon: answering *{incident['id']}* — "
                        f"_{' '.join(text.split())[:250]}_",
                    }
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": answer[:2900]}},
        ],
        thread_ts=thread_ts,
    )
    log.info("slack.answered", incident_id=incident["id"], chars=len(answer))


async def handle_interaction(payload: dict[str, Any]) -> None:
    """Handle a Block Kit button press (approve/reject containment)."""
    if payload.get("type") != "block_actions":
        return

    actions = payload.get("actions", []) or []
    if not actions:
        return

    action = actions[0]
    action_id = action.get("action_id", "")
    incident_id = action.get("value", "")
    user = (payload.get("user") or {}).get("id", "unknown")
    container = payload.get("container") or {}
    channel = (payload.get("channel") or {}).get("id", "")
    thread_ts = container.get("thread_ts") or container.get("message_ts", "")

    if action_id not in {"approve_all", "reject_all"} or not incident_id:
        return

    record = await incidents.get_incident(incident_id)
    if record is None:
        await notifier.post(channel, text=f"Unknown incident `{incident_id}`.", thread_ts=thread_ts)
        return

    approved = action_id == "approve_all"
    pending = [a for a in record.get("containment_actions", []) if a.get("requires_approval")]

    decision = {
        "approved_all": approved,
        "approved_actions": [a["action"] for a in pending] if approved else [],
        "approver": user,
        "note": "approved via Slack" if approved else "rejected via Slack",
    }

    await notifier.post(
        channel,
        text=blocks.decision_receipt(incident_id, user, approved, len(pending)),
        thread_ts=thread_ts,
    )
    await runner.resume_investigation(incident_id, decision)
    log.info("slack.approval_handled", incident_id=incident_id, user=user, approved=approved)


async def handle_slash_command(form: dict[str, str]) -> dict[str, Any]:
    """`/ir <question>` — synchronous ack, background investigation."""
    text = clean_text(form.get("text", ""))
    channel = form.get("channel_id", "")
    user = form.get("user_id", "")

    if not text:
        return {
            "response_type": "ephemeral",
            "text": "Usage: `/ir <what to investigate>` — e.g. `/ir suspicious login from 203.0.113.7`",
        }

    async def _start() -> None:
        # start_investigation opens the thread and acknowledges in it, so the
        # run has somewhere to narrate from its first step.
        await runner.start_investigation(
            question=text,
            alert={"title": text[:200], "reported_by": user, "raw": text},
            source="slack",
            slack_channel=channel,
        )

    _spawn(_start())
    return {"response_type": "in_channel", "text": f":mag: Starting investigation: _{text[:150]}_"}


def slack_enabled() -> bool:
    settings = get_settings()
    return settings.slack_enabled and bool(settings.slack_bot_token)
