"""Per-incident spend and access, and the honesty of what it reports.

This is the audit record for a system that can reach into production, so the
failure that matters is not an inaccurate token count — it is a tool call that
happened and was not written down.
"""

from __future__ import annotations

import pytest

from app.services import ledger


@pytest.fixture(autouse=True)
def _clean() -> None:
    ledger._pending.clear()


def test_nothing_is_recorded_outside_an_incident() -> None:
    """A model call from a Slack answer or a test harness has no incident to
    bill, and inventing one would corrupt somebody else's record."""
    ledger.record_llm(role="critic", input_tokens=100, output_tokens=50)
    assert ledger.take("anything") == []


def test_calls_are_attributed_to_the_bound_incident() -> None:
    with ledger.bind(incident_id="INC-1"):
        ledger.record_llm(role="critic", model="m", input_tokens=100, output_tokens=50)
    entries = ledger.take("INC-1")
    assert len(entries) == 1
    assert entries[0]["role"] == "critic"
    assert entries[0]["input_tokens"] == 100


def test_the_actor_overrides_the_role_so_specialists_are_distinguishable() -> None:
    """All three specialists share the `specialist` role. Reporting them as one
    line hides the whole point of the fan-out."""
    with ledger.bind(incident_id="INC-1"):
        with ledger.bind(actor="triage"):
            ledger.record_llm(role="specialist", input_tokens=10, output_tokens=1)
        with ledger.bind(actor="behavioral"):
            ledger.record_llm(role="specialist", input_tokens=20, output_tokens=2)
    actors = [e["actor"] for e in ledger.take("INC-1")]
    assert actors == ["triage", "behavioral"]


def test_the_binding_is_restored_when_the_block_ends() -> None:
    with ledger.bind(incident_id="INC-1", actor="triage"):
        assert ledger.current() == ("INC-1", "triage")
        with ledger.bind(actor="critic"):
            assert ledger.current() == ("INC-1", "critic")
        assert ledger.current() == ("INC-1", "triage")
    assert ledger.current() == ("", "")


def test_taking_the_buffer_empties_it() -> None:
    """Flushing twice must not bill the same call twice."""
    with ledger.bind(incident_id="INC-1"):
        ledger.record_llm(role="critic", input_tokens=1, output_tokens=1)
    assert len(ledger.take("INC-1")) == 1
    assert ledger.take("INC-1") == []


def test_a_failed_call_is_still_recorded() -> None:
    """The expensive failures are exactly the ones worth seeing."""
    with ledger.bind(incident_id="INC-1"):
        ledger.record_llm(role="critic", outcome="error")
    assert ledger.take("INC-1")[0]["outcome"] == "error"


def test_a_tool_call_records_what_it_was_pointed_at() -> None:
    with ledger.bind(incident_id="INC-1", actor="enrichment"):
        ledger.record_tool(tool="enrich_ioc", target="ioc_value=185.65.135.42")
    entry = ledger.take("INC-1")[0]
    assert entry["kind"] == "tool"
    assert entry["actor"] == "enrichment"
    assert "185.65.135.42" in entry["target"]


def test_an_enormous_target_is_truncated_not_stored_whole() -> None:
    with ledger.bind(incident_id="INC-1"):
        ledger.record_tool(tool="hunt_query", target="x" * 5000)
    assert len(ledger.take("INC-1")[0]["target"]) == 200


# ── Reading it back ──────────────────────────────────────────────────────────
def usage(*entries: dict) -> dict:
    return {"usage": list(entries)}


def llm(actor: str, tin: int, tout: int, **kw) -> dict:
    return {"kind": "llm", "actor": actor, "input_tokens": tin, "output_tokens": tout, **kw}


def test_agents_are_ranked_by_what_they_spent() -> None:
    result = ledger.summarise(
        usage(llm("triage", 100, 20), llm("behavioral", 900, 100), llm("critic", 300, 50))
    )
    assert [a["actor"] for a in result["agents"]] == ["behavioral", "critic", "triage"]
    assert result["total_tokens"] == 1470


def test_the_bar_is_relative_to_the_biggest_spender() -> None:
    """Relative to the total, a dominant agent flattens everything else to a
    sliver and the chart stops showing anything."""
    result = ledger.summarise(usage(llm("a", 1000, 0), llm("b", 250, 0)))
    assert result["agents"][0]["share"] == 100
    assert result["agents"][1]["share"] == 25
    # The percentage of the whole is a separate, honest number.
    assert result["agents"][1]["pct"] == 20


def test_repeated_calls_by_one_agent_are_summed() -> None:
    result = ledger.summarise(usage(llm("triage", 100, 10), llm("triage", 50, 5)))
    assert len(result["agents"]) == 1
    assert result["agents"][0]["calls"] == 2
    assert result["agents"][0]["tokens"] == 165


def test_tools_are_grouped_with_who_called_them_and_against_what() -> None:
    result = ledger.summarise(
        usage(
            {"kind": "tool", "actor": "enrichment", "tool": "enrich_ioc", "target": "ip=1.1.1.1"},
            {"kind": "tool", "actor": "triage", "tool": "enrich_ioc", "target": "ip=2.2.2.2"},
        )
    )
    tool = result["tools"][0]
    assert tool["calls"] == 2
    assert tool["by"] == ["enrichment", "triage"]
    assert tool["targets"] == ["ip=1.1.1.1", "ip=2.2.2.2"]


def test_a_provider_that_withholds_usage_is_reported_not_hidden() -> None:
    """Zero tokens against real calls means the provider did not say, which is
    a different fact from 'this run was free'."""
    result = ledger.summarise(usage(llm("critic", 0, 0)))
    assert result["tokens_unreported"] is True
    assert result["llm_calls"] == 1


def test_an_incident_with_no_usage_says_so_rather_than_rendering_empty() -> None:
    result = ledger.summarise({})
    assert result["empty"] is True
    assert result["agents"] == [] and result["tools"] == []
    assert result["tokens_unreported"] is False


def test_failures_are_counted_per_agent_and_per_tool() -> None:
    result = ledger.summarise(
        usage(
            llm("critic", 10, 1, outcome="error"),
            {"kind": "tool", "actor": "triage", "tool": "enrich_ioc", "outcome": "error"},
        )
    )
    assert next(a for a in result["agents"] if a["actor"] == "critic")["failures"] == 1
    assert result["tools"][0]["failures"] == 1
