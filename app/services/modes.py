"""How much rope the bot has on a given incident.

One agent, three postures. The same investigation machinery runs underneath;
what changes is whether it speaks unprompted, whether it investigates without
being asked, and whether it is allowed to touch anything.

    spectator   passive. Answers when spoken to, privately to the asker, and
                does nothing otherwise. The default, and where every incident
                starts.
    winger      investigates on its own as data lands, checks in every ten
                minutes, and proposes actions — but a human approves each one.
    responder   investigates and acts, stopping only at the risk ceiling.

The ladder only unlocks once the channel has been open a few minutes. That is
deliberate: the first minutes of an incident are when the picture is worst and
the temptation to hand over control is highest, and a responder who has not yet
read the first update is not in a position to judge whether the bot should be
allowed to disable an account.

The risk ceiling is the part worth arguing about. Fully autonomous containment
sounds like the point of the exercise right up until the run proposes
`disable_account` on a named person, or an irreversible token revocation, on
evidence that later turns out to be a misread. So `responder` is autonomous up
to a ceiling and gates everything above it. Setting IR_AUTONOMOUS_MAX_RISK=all
removes the ceiling; that is a decision an operator makes on purpose, not a
default they inherit.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

SPECTATOR = "spectator"
WINGER = "winger"
RESPONDER = "responder"


@dataclass(frozen=True)
class Mode:
    key: str
    label: str
    #: One line, shown when the mode is set and in the channel topic.
    blurb: str
    #: Run the graph when new information arrives, without being asked.
    investigates: bool
    #: Seconds between catch-up digests; 0 means never.
    digest_seconds: int
    #: Execute anything at all.
    acts: bool
    #: Post replies where everyone can see them, rather than only the asker.
    replies_in_channel: bool


MODES: dict[str, Mode] = {
    SPECTATOR: Mode(
        key=SPECTATOR,
        label="Spectator",
        blurb="Answers when asked, privately. Investigates nothing on its own, touches nothing.",
        investigates=False,
        digest_seconds=0,
        acts=False,
        replies_in_channel=False,
    ),
    WINGER: Mode(
        key=WINGER,
        label="Winger",
        blurb="Triages and gathers on its own, checks in every 10 minutes, asks before acting.",
        investigates=True,
        digest_seconds=600,
        acts=True,
        replies_in_channel=True,
    ),
    RESPONDER: Mode(
        key=RESPONDER,
        label="Incident Responder",
        blurb="Investigates and acts autonomously, up to the risk ceiling.",
        investigates=True,
        digest_seconds=600,
        acts=True,
        replies_in_channel=True,
    ),
}

DEFAULT = SPECTATOR

#: Aliases people will actually type. "wingman" is what everyone says out loud.
_ALIASES = {
    "watch": SPECTATOR,
    "observe": SPECTATOR,
    "passive": SPECTATOR,
    "wingman": WINGER,
    "wing": WINGER,
    "copilot": WINGER,
    "co-pilot": WINGER,
    "auto": RESPONDER,
    "autonomous": RESPONDER,
    "ir": RESPONDER,
    "responder": RESPONDER,
}


def resolve(name: str) -> Mode | None:
    """Map whatever someone typed onto a mode, or None if it is not one."""
    key = (name or "").strip().lower().replace("_", "-")
    key = _ALIASES.get(key, key)
    return MODES.get(key)


def get(key: str | None) -> Mode:
    return MODES.get(str(key or ""), MODES[DEFAULT])


# ── The risk ceiling ─────────────────────────────────────────────────────────
_RISK_ORDER = {"low": 0, "medium": 1, "high": 2}


def _ceiling(configured: str) -> int:
    """Highest risk level the bot may execute unattended. -1 disables autonomy."""
    value = (configured or "medium").strip().lower()
    if value in {"all", "any", "*"}:
        return 99
    if value in {"none", "off"}:
        return -1
    return _RISK_ORDER.get(value, 1)


def may_execute_unattended(action: dict[str, Any], mode: Mode, max_risk: str) -> bool:
    """Whether this one action can run without a human in responder mode.

    Irreversibility is a harder stop than risk. A reversible high-risk action is
    a bad afternoon; an irreversible one is a decision nobody gets to revisit,
    and the agent should not be the last thing that touched it — unless the
    operator has explicitly lifted the ceiling to `all`.
    """
    if mode.key != RESPONDER or not mode.acts:
        return False
    ceiling = _ceiling(max_risk)
    if ceiling < 0:
        return False
    if ceiling >= 99:
        return True
    if not action.get("reversible", True):
        return False
    return _RISK_ORDER.get(str(action.get("risk", "medium")).lower(), 1) <= ceiling


def apply_to_actions(
    actions: list[dict[str, Any]], mode: Mode, max_risk: str
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Re-decide `requires_approval` for each action under the active mode.

    Returns the actions plus what was cleared for autonomous execution and what
    still needs a human, so the channel can be told which is which rather than
    discovering it from behaviour.
    """
    autonomous: list[str] = []
    gated: list[str] = []
    out: list[dict[str, Any]] = []
    for action in actions:
        item = dict(action)
        if item.get("requires_approval") and may_execute_unattended(item, mode, max_risk):
            item["requires_approval"] = False
            item["autonomous"] = True
            autonomous.append(str(item.get("action", "")))
        elif item.get("requires_approval"):
            gated.append(str(item.get("action", "")))
        out.append(item)
    return out, autonomous, gated


# ── The unlock ───────────────────────────────────────────────────────────────
def unlocked(opened_at: datetime | None, *, after_seconds: int) -> bool:
    """Whether the ladder is available yet on a channel opened at `opened_at`."""
    if after_seconds <= 0:
        return True
    if opened_at is None:
        return False
    if opened_at.tzinfo is None:
        opened_at = opened_at.replace(tzinfo=UTC)
    return (datetime.now(UTC) - opened_at).total_seconds() >= after_seconds


def seconds_until_unlock(opened_at: datetime | None, *, after_seconds: int) -> int:
    if unlocked(opened_at, after_seconds=after_seconds):
        return 0
    if opened_at is None:
        return after_seconds
    if opened_at.tzinfo is None:
        opened_at = opened_at.replace(tzinfo=UTC)
    elapsed = (datetime.now(UTC) - opened_at).total_seconds()
    return max(0, int(after_seconds - elapsed))


def choices() -> str:
    """The one-line menu, for a Slack reply."""
    return " · ".join(f"`{m.key}` {m.label}" for m in MODES.values())
