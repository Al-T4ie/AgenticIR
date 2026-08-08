"""End-to-end graph behaviour: fan-out, critic loop, HITL interrupt."""

from __future__ import annotations

from typing import Any

import pytest
from langgraph.types import Command

from app.graph.state import new_state


def _config(thread: str) -> dict[str, Any]:
    return {"configurable": {"thread_id": thread}, "recursion_limit": 60}


def _state(alert: dict[str, Any], thread: str = "t1") -> Any:
    return new_state(incident_id="INC-TEST-0001", thread_id=thread, source="test", alert=alert)


async def test_investigation_reaches_approval_then_completes(graph, scripted_llm, sample_alert):
    """A high-severity true positive with a risky action must pause for a human."""
    config = _config("t-approval")

    await graph.ainvoke(_state(sample_alert, "t-approval"), config=config)

    snapshot = await graph.aget_state(config)
    interrupts = list(snapshot.interrupts or [])
    assert interrupts, "expected the graph to pause on the containment approval gate"

    payload = getattr(interrupts[0], "value", interrupts[0])
    assert payload["kind"] == "containment_approval"
    assert payload["actions"], "the approval prompt must list the actions being approved"
    assert payload["actions"][0]["action"] == "isolate_host"

    # Nothing is executed while the graph is parked.
    assert not snapshot.values.get("executed_actions")

    # Resume with a human decision.
    await graph.ainvoke(
        Command(
            resume={
                "approved_all": True,
                "approved_actions": ["isolate_host"],
                "approver": "U123ANALYST",
            }
        ),
        config=config,
    )

    final = (await graph.aget_state(config)).values
    assert final["status"] == "completed"
    assert final["report"]
    assert final["approval"]["approver"] == "U123ANALYST"
    assert any(t["actor"] == "human:U123ANALYST" for t in final["timeline"])


async def test_specialists_fan_out_in_parallel(graph, scripted_llm, sample_alert):
    """Every planned specialist runs and contributes findings in one round."""
    scripted_llm["plan_per_round"] = [["triage", "enrichment", "behavioral"]]
    scripted_llm["containment"] = []  # no approval gate, run straight through

    config = _config("t-fanout")
    await graph.ainvoke(_state(sample_alert, "t-fanout"), config=config)
    final = (await graph.aget_state(config)).values

    specialists = {f["specialist"] for f in final["findings"]}
    assert specialists == {"triage", "enrichment", "behavioral"}
    assert len(final["findings"]) == 3, "additive reducer should keep every finding"
    assert final["status"] == "completed"


async def test_critic_can_request_another_round(graph, scripted_llm, sample_alert):
    """When the critic is unsatisfied, the supervisor plans again."""
    scripted_llm["plan_per_round"] = [["triage"], ["enrichment"]]
    scripted_llm["needs_more_work"] = True
    scripted_llm["containment"] = []

    config = _config("t-loop")
    await graph.ainvoke(_state(sample_alert, "t-loop"), config=config)
    final = (await graph.aget_state(config)).values

    # Round cap is 3 by default; the scripted critic always asks for more, so the
    # cap is what must stop it.
    assert final["round"] == 3, f"expected the round cap to halt the loop, got {final['round']}"
    assert final["status"] == "completed"
    assert scripted_llm["supervisor_rounds"] == 3


async def test_false_positive_proposes_no_containment(graph, scripted_llm, sample_alert):
    scripted_llm["verdict"] = "false_positive"
    scripted_llm["severity"] = "low"

    config = _config("t-fp")
    await graph.ainvoke(_state(sample_alert, "t-fp"), config=config)
    final = (await graph.aget_state(config)).values

    assert final["verdict"] == "false_positive"
    assert final["containment_actions"] == []
    assert final["status"] == "completed"
    # Went straight through the executor without an approval pause.
    assert not (await graph.aget_state(config)).interrupts


async def test_rejected_containment_executes_nothing(graph, scripted_llm, sample_alert):
    config = _config("t-reject")
    await graph.ainvoke(_state(sample_alert, "t-reject"), config=config)

    await graph.ainvoke(
        Command(resume={"approved_all": False, "approved_actions": [], "approver": "U9"}),
        config=config,
    )
    final = (await graph.aget_state(config)).values

    assert final["executed_actions"] == []
    assert final["approval"]["approved_actions"] == []
    assert final["status"] == "completed"


async def test_state_survives_a_new_graph_instance(scripted_llm, sample_alert):
    """Checkpointed state can be resumed by a different compiled graph object —
    the property that lets a run survive a container restart."""
    from langgraph.checkpoint.memory import MemorySaver

    from app.graph.builder import build_graph

    saver = MemorySaver()
    config = _config("t-durable")

    first = build_graph().compile(checkpointer=saver)
    await first.ainvoke(_state(sample_alert, "t-durable"), config=config)
    assert (await first.aget_state(config)).interrupts

    # Simulate a restart: brand new compiled graph, same checkpointer.
    second = build_graph().compile(checkpointer=saver)
    await second.ainvoke(
        Command(resume={"approved_all": True, "approver": "U-after-restart"}), config=config
    )

    final = (await second.aget_state(config)).values
    assert final["status"] == "completed"
    assert final["approval"]["approver"] == "U-after-restart"


async def test_specialist_failure_degrades_gracefully(
    graph, scripted_llm, sample_alert, monkeypatch
):
    """One dead specialist must not kill the investigation."""
    from app.graph import llm as llm_module
    from app.graph.nodes.specialist import SpecialistReport

    original = llm_module.structured

    async def flaky(role: str, schema: type, messages: list[Any]) -> Any:
        if schema is SpecialistReport:
            raise RuntimeError("model provider returned 503")
        return await original(role, schema, messages)

    monkeypatch.setattr(llm_module, "structured", flaky)
    scripted_llm["containment"] = []

    config = _config("t-degraded")
    await graph.ainvoke(_state(sample_alert, "t-degraded"), config=config)
    final = (await graph.aget_state(config)).values

    assert final["status"] == "completed", "run should finish despite specialist failures"
    assert final["errors"], "the failure must be recorded on the incident"
    assert any("503" in e for e in final["errors"])


@pytest.mark.parametrize(
    ("severity", "threshold", "expected"),
    [
        ("critical", "low", True),
        ("low", "low", True),
        ("informational", "low", False),
        ("high", "never", True),
        ("informational", "never", True),
        ("medium", "high", False),
    ],
)
def test_severity_threshold(severity: str, threshold: str, expected: bool):
    from app.config import severity_at_least

    assert severity_at_least(severity, threshold) is expected
