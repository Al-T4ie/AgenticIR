"""The autonomy ladder, and the ceiling that stops it running away.

This module decides what a machine may do to production without asking anyone.
Every rule in it is one someone will eventually want to argue with, so each is
pinned by a test that says what the rule is and why it is that way round.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.services import modes


def action(name: str = "block_ip", *, risk: str = "low", reversible: bool = True) -> dict:
    return {"action": name, "risk": risk, "reversible": reversible, "requires_approval": True}


# ── Naming ───────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("spectator", modes.SPECTATOR),
        ("SPECTATOR", modes.SPECTATOR),
        ("  watch  ", modes.SPECTATOR),
        ("wingman", modes.WINGER),
        ("winger", modes.WINGER),
        ("co-pilot", modes.WINGER),
        ("responder", modes.RESPONDER),
        ("auto", modes.RESPONDER),
        ("autonomous", modes.RESPONDER),
    ],
)
def test_people_get_the_mode_they_meant(typed: str, expected: str) -> None:
    """Nobody types the canonical name. `wingman` is what they say out loud."""
    resolved = modes.resolve(typed)
    assert resolved is not None and resolved.key == expected


@pytest.mark.parametrize("typed", ["", "   ", "godmode", "yolo", "respond er"])
def test_a_mode_that_does_not_exist_is_not_invented(typed: str) -> None:
    assert modes.resolve(typed) is None


def test_an_unknown_stored_mode_falls_back_to_the_safest() -> None:
    """A corrupt or future value in the column must not grant autonomy."""
    assert modes.get("something-we-removed").key == modes.SPECTATOR
    assert modes.get(None).key == modes.SPECTATOR
    assert modes.get("").key == modes.SPECTATOR


# ── What each mode is for ────────────────────────────────────────────────────
def test_spectator_does_nothing_unprompted() -> None:
    m = modes.MODES[modes.SPECTATOR]
    assert not m.investigates
    assert not m.acts
    assert m.digest_seconds == 0
    assert not m.replies_in_channel, "spectator answers privately to the asker"


def test_winger_investigates_and_checks_in_but_still_asks() -> None:
    m = modes.MODES[modes.WINGER]
    assert m.investigates and m.acts
    assert m.digest_seconds == 600
    assert not modes.may_execute_unattended(action(), m, "all"), (
        "winger proposes; only responder executes unattended, whatever the ceiling"
    )


def test_responder_acts_within_the_ceiling() -> None:
    m = modes.MODES[modes.RESPONDER]
    assert modes.may_execute_unattended(action(risk="low"), m, "medium")
    assert modes.may_execute_unattended(action(risk="medium"), m, "medium")
    assert not modes.may_execute_unattended(action(risk="high"), m, "medium")


# ── The ceiling ──────────────────────────────────────────────────────────────
def test_irreversible_is_a_harder_stop_than_risk() -> None:
    """A reversible high-risk action is a bad afternoon. An irreversible one is
    a decision nobody gets to revisit."""
    m = modes.MODES[modes.RESPONDER]
    assert not modes.may_execute_unattended(action(risk="low", reversible=False), m, "high")


def test_the_ceiling_can_be_lifted_entirely_but_only_on_purpose() -> None:
    m = modes.MODES[modes.RESPONDER]
    irreversible = action(risk="high", reversible=False)
    assert not modes.may_execute_unattended(irreversible, m, "high")
    assert modes.may_execute_unattended(irreversible, m, "all")


def test_autonomy_can_be_switched_off_without_leaving_responder_mode() -> None:
    m = modes.MODES[modes.RESPONDER]
    assert not modes.may_execute_unattended(action(risk="low"), m, "none")


def test_an_unparseable_ceiling_lands_on_medium_not_on_everything() -> None:
    """A typo in an env var must not silently grant more autonomy than intended."""
    m = modes.MODES[modes.RESPONDER]
    assert modes.may_execute_unattended(action(risk="medium"), m, "moderate-ish")
    assert not modes.may_execute_unattended(action(risk="high"), m, "moderate-ish")


def test_a_missing_risk_field_is_treated_as_medium() -> None:
    m = modes.MODES[modes.RESPONDER]
    assert modes.may_execute_unattended({"action": "x", "requires_approval": True}, m, "medium")
    assert not modes.may_execute_unattended({"action": "x", "requires_approval": True}, m, "low")


# ── Applying it to a plan ────────────────────────────────────────────────────
def test_the_plan_is_split_into_what_runs_and_what_waits() -> None:
    plan = [
        action("enrich_ioc", risk="low"),
        action("disable_account", risk="high"),
        action("revoke_oauth_token", risk="low", reversible=False),
    ]
    out, autonomous, gated = modes.apply_to_actions(plan, modes.MODES[modes.RESPONDER], "medium")
    assert autonomous == ["enrich_ioc"]
    assert sorted(gated) == ["disable_account", "revoke_oauth_token"]
    assert out[0]["requires_approval"] is False
    assert out[0]["autonomous"] is True
    assert out[1]["requires_approval"] is True
    assert "autonomous" not in out[1]


def test_applying_a_mode_never_gates_something_that_was_already_clear() -> None:
    """The mode widens what may run; it must not narrow it and quietly stall a
    plan the containment policy had already cleared."""
    free = {"action": "hunt_query", "risk": "low", "reversible": True, "requires_approval": False}
    out, autonomous, gated = modes.apply_to_actions([free], modes.MODES[modes.SPECTATOR], "none")
    assert out[0]["requires_approval"] is False
    assert autonomous == [] and gated == []


def test_spectator_leaves_every_gate_standing() -> None:
    plan = [action("enrich_ioc", risk="low")]
    out, autonomous, gated = modes.apply_to_actions(plan, modes.MODES[modes.SPECTATOR], "all")
    assert out[0]["requires_approval"] is True
    assert autonomous == [] and gated == ["enrich_ioc"]


def test_the_input_plan_is_not_mutated() -> None:
    plan = [action("enrich_ioc", risk="low")]
    modes.apply_to_actions(plan, modes.MODES[modes.RESPONDER], "medium")
    assert plan[0]["requires_approval"] is True, "callers keep the original for the audit record"


# ── The unlock ───────────────────────────────────────────────────────────────
def test_the_ladder_is_locked_for_the_first_few_minutes() -> None:
    just_now = datetime.now(UTC)
    assert not modes.unlocked(just_now, after_seconds=300)
    assert modes.seconds_until_unlock(just_now, after_seconds=300) > 250


def test_the_ladder_unlocks_once_the_room_has_been_open_long_enough() -> None:
    earlier = datetime.now(UTC) - timedelta(seconds=301)
    assert modes.unlocked(earlier, after_seconds=300)
    assert modes.seconds_until_unlock(earlier, after_seconds=300) == 0


def test_an_incident_with_no_room_is_locked() -> None:
    """No channel means nobody has read anything, so nobody can hand over."""
    assert not modes.unlocked(None, after_seconds=300)


def test_a_naive_timestamp_is_read_as_utc_not_local() -> None:
    """Postgres hands back naive datetimes on some drivers; treating those as
    local time would unlock the ladder hours early or late."""
    earlier = (datetime.now(UTC) - timedelta(seconds=400)).replace(tzinfo=None)
    assert modes.unlocked(earlier, after_seconds=300)


def test_the_unlock_can_be_disabled() -> None:
    assert modes.unlocked(None, after_seconds=0)
