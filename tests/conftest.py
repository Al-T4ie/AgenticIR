"""Shared fixtures.

The graph tests run the real topology against a scripted model, so they
exercise fan-out, the critic loop and the HITL interrupt with no network calls
and no API keys.
"""

from __future__ import annotations

import os
from typing import Any

import pytest

# Must be set before app.config is first imported.
os.environ.setdefault("API_KEY", "test-api-key")
os.environ.setdefault("SLACK_SIGNING_SECRET", "test-signing-secret")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-anthropic-key")
os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SLACK_ENABLED", "false")
os.environ.setdefault("N8N_ENABLED", "false")

from langchain_core.messages import AIMessage  # noqa: E402


class FakeChatModel:
    """Minimal stand-in for a chat model in the specialist tool loop."""

    def __init__(self, reply: str = "Investigated; nothing further to query.") -> None:
        self.reply = reply
        self.calls = 0

    def bind_tools(self, tools: list[Any]) -> FakeChatModel:  # noqa: ARG002
        return self

    async def ainvoke(self, messages: list[Any]) -> AIMessage:  # noqa: ARG002
        self.calls += 1
        # No tool_calls -> the loop exits after one pass.
        return AIMessage(content=self.reply)


@pytest.fixture
def scripted_llm(monkeypatch: pytest.MonkeyPatch):
    """Patch the LLM layer with deterministic, schema-aware responses.

    Returns a recorder dict so tests can assert on what each role was asked.
    """
    from app.graph import llm as llm_module
    from app.graph.nodes.containment import ContainmentPlan, ProposedAction
    from app.graph.nodes.critic import Review
    from app.graph.nodes.specialist import ReportedFinding, SpecialistReport
    from app.graph.nodes.supervisor import Plan, PlannedTask

    recorder: dict[str, Any] = {
        "roles": [],
        "schemas": [],
        "supervisor_rounds": 0,
        "plan_per_round": [["triage", "enrichment"]],
        "needs_more_work": False,
        "verdict": "true_positive",
        "severity": "high",
        "containment": [
            ProposedAction(
                action="isolate_host",
                target="FIN-WS-04",
                justification="Confirmed C2 beaconing from this host.",
                reversible=True,
                risk="high",
                tool="",
            )
        ],
        "report_text": "*Verdict:* true positive\n\nScripted report body.",
    }

    async def fake_structured(role: str, schema: type, messages: list[Any]) -> Any:  # noqa: ARG001
        recorder["roles"].append(role)
        recorder["schemas"].append(schema.__name__)

        if schema is Plan:
            idx = recorder["supervisor_rounds"]
            recorder["supervisor_rounds"] += 1
            plans = recorder["plan_per_round"]
            names = plans[idx] if idx < len(plans) else []
            return Plan(
                reasoning="scripted",
                tasks=[PlannedTask(specialist=n, objective=f"investigate via {n}") for n in names],
            )

        if schema is SpecialistReport:
            return SpecialistReport(
                findings=[
                    ReportedFinding(
                        title="Scripted finding",
                        detail="Something notable was observed.",
                        severity="high",
                        confidence=0.8,
                        iocs=["198.51.100.77"],
                        mitre_techniques=["T1059.001"],
                        evidence=["scripted evidence"],
                    )
                ],
                gaps="",
            )

        if schema is Review:
            return Review(
                verdict=recorder["verdict"],
                severity=recorder["severity"],
                confidence=0.85,
                summary="Scripted review summary.",
                needs_more_work=recorder["needs_more_work"],
                feedback="chase the beacon domain" if recorder["needs_more_work"] else "",
            )

        if schema is ContainmentPlan:
            return ContainmentPlan(actions=list(recorder["containment"]), reasoning="scripted")

        raise AssertionError(f"unexpected schema {schema!r}")

    async def fake_text(role: str, messages: list[Any]) -> str:  # noqa: ARG001
        recorder["roles"].append(role)
        return recorder["report_text"]

    monkeypatch.setattr(llm_module, "structured", fake_structured)
    monkeypatch.setattr(llm_module, "text", fake_text)
    monkeypatch.setattr(llm_module, "get_llm", lambda role="specialist": FakeChatModel())  # noqa: ARG005
    return recorder


@pytest.fixture
async def graph():
    """A freshly compiled graph with an in-memory checkpointer."""
    from langgraph.checkpoint.memory import MemorySaver

    from app.graph.builder import build_graph

    return build_graph().compile(checkpointer=MemorySaver())


@pytest.fixture
def sample_alert() -> dict[str, Any]:
    return {
        "title": "Encoded PowerShell spawned by Outlook",
        "severity": "high",
        "host": {"hostname": "FIN-WS-04", "ip": "10.4.2.19"},
        "detail": (
            "Outlook spawned powershell.exe with an encoded command, then "
            "connected to 198.51.100.77 and cdn-update-service.top repeatedly."
        ),
    }
