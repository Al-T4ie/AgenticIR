"""Block Kit builders for the analyst-facing Slack surface."""

from __future__ import annotations

from typing import Any

SEVERITY_EMOJI = {
    "critical": ":rotating_light:",
    "high": ":red_circle:",
    "medium": ":large_orange_circle:",
    "low": ":large_yellow_circle:",
    "informational": ":large_blue_circle:",
}

VERDICT_EMOJI = {
    "true_positive": ":dart:",
    "false_positive": ":white_check_mark:",
    "inconclusive": ":grey_question:",
}

# Slack rejects text objects over 3000 chars; keep a margin for the ellipsis.
_MAX_TEXT = 2900


def _truncate(text: str, limit: int = _MAX_TEXT) -> str:
    return text if len(text) <= limit else text[: limit - 20].rstrip() + "\n… _(truncated)_"


def _section(text: str) -> dict[str, Any]:
    return {"type": "section", "text": {"type": "mrkdwn", "text": _truncate(text)}}


def acknowledgement(incident_id: str, title: str) -> list[dict[str, Any]]:
    return [
        _section(
            f":mag: Investigating *{title}*\nIncident `{incident_id}` — I'll report back here."
        ),
        {
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": "Agents dispatched · this usually takes 30–90 seconds"}
            ],
        },
    ]


def report_message(incident: dict[str, Any], public_base_url: str = "") -> list[dict[str, Any]]:
    severity = incident.get("severity", "informational")
    verdict = incident.get("verdict", "inconclusive")
    incident_id = incident.get("id", "")

    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{SEVERITY_EMOJI.get(severity, '')} {severity.upper()} — "
                f"{verdict.replace('_', ' ').title()}"[:150],
            },
        },
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"`{incident_id}` · {VERDICT_EMOJI.get(verdict, '')} "
                    f"confidence {float(incident.get('confidence', 0) or 0):.0%} · "
                    f"{len(incident.get('findings', []))} findings",
                }
            ],
        },
    ]

    report = incident.get("report") or incident.get("summary") or "_No report produced._"
    # Long reports get split across sections rather than silently cut off.
    for chunk in _chunk(report, _MAX_TEXT):
        blocks.append(_section(chunk))

    actions = incident.get("containment_actions", [])
    if actions:
        listed = "\n".join(
            f"• *{a.get('action')}* → `{a.get('target')}`"
            f"{' :lock: _approval required_' if a.get('requires_approval') else ''}"
            for a in actions[:10]
        )
        blocks.append({"type": "divider"})
        blocks.append(_section(f"*Proposed actions*\n{listed}"))

    if public_base_url:
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in dashboard"},
                        "url": f"{public_base_url.rstrip('/')}/ui/incidents/{incident_id}",
                    }
                ],
            }
        )
    return blocks


def approval_request(incident_id: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    actions = payload.get("actions", [])
    listed = (
        "\n".join(
            f"• *{a.get('action')}* → `{a.get('target')}`\n   _{a.get('justification', '')[:200]}_"
            f"\n   risk: {a.get('risk', 'unknown')} · "
            f"{'reversible' if a.get('reversible') else ':warning: *not reversible*'}"
            for a in actions[:10]
        )
        or "_No actions listed._"
    )

    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": ":lock: Containment approval required"},
        },
        _section(
            f"`{incident_id}` — *{payload.get('severity', '?')}* / "
            f"{payload.get('verdict', '?')}\n{payload.get('summary', '')}"
        ),
        {"type": "divider"},
        _section(f"*Requested actions*\n{listed}"),
        {
            "type": "actions",
            "block_id": f"approval::{incident_id}",
            "elements": [
                {
                    "type": "button",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Approve all"},
                    "action_id": "approve_all",
                    "value": incident_id,
                    "confirm": {
                        "title": {"type": "plain_text", "text": "Execute containment?"},
                        "text": {
                            "type": "mrkdwn",
                            "text": f"This runs {len(actions)} action(s) against live systems.",
                        },
                        "confirm": {"type": "plain_text", "text": "Execute"},
                        "deny": {"type": "plain_text", "text": "Cancel"},
                    },
                },
                {
                    "type": "button",
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Reject all"},
                    "action_id": "reject_all",
                    "value": incident_id,
                },
            ],
        },
    ]


def decision_receipt(incident_id: str, approver: str, approved: bool, count: int) -> str:
    if approved:
        return f":white_check_mark: <@{approver}> approved {count} action(s) for `{incident_id}`. Executing…"
    return f":no_entry: <@{approver}> rejected containment for `{incident_id}`. No actions taken."


def error_message(incident_id: str, detail: str) -> list[dict[str, Any]]:
    return [
        _section(
            f":warning: Investigation `{incident_id}` failed.\n```{detail[:1500]}```\n"
            "The incident record is preserved — resume or retry from the dashboard."
        )
    ]


def _chunk(text: str, size: int) -> list[str]:
    """Split on paragraph boundaries where possible so blocks stay readable."""
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    current = ""
    for para in text.split("\n\n"):
        candidate = f"{current}\n\n{para}" if current else para
        if len(candidate) > size and current:
            chunks.append(current)
            current = para
        else:
            current = candidate
    if current:
        chunks.append(current)
    return [c[:size] for c in chunks[:8]]
