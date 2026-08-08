"""Graph topology.

    START → intake → supervisor ─┬─(Send × N)→ specialist ─┐
                                 │                          ├→ critic ─┬→ supervisor  (another round)
                                 └──────────(no tasks)──────┘          └→ containment
                                                                             │
                                              report ← execute ← approval ←──┤
                                                │           ↑                │
                                               END          └────(auto-approved)

The fan-out uses `Send`, so specialists run concurrently in a single superstep
and the `specialist → critic` edge only fires once they have all returned.
"""

from __future__ import annotations

from typing import Any, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from app.config import get_settings
from app.graph.nodes.containment import approval_node, containment_node, execute_node
from app.graph.nodes.critic import critic_node
from app.graph.nodes.intake import intake_node
from app.graph.nodes.report import report_node
from app.graph.nodes.specialist import specialist_node
from app.graph.nodes.supervisor import supervisor_node
from app.graph.state import IncidentState
from app.observability import get_logger
from app.tools.builtin import alert_to_text

log = get_logger(__name__)


def _dispatch(state: IncidentState) -> list[Send] | Literal["critic"]:
    """Fan out to every planned specialist at once."""
    plan = state.get("plan", []) or []
    if not plan:
        return "critic"

    alert_text = alert_to_text(state.get("alert", {}))
    prior = (
        "\n".join(
            f"- [{f.get('specialist')}] {f.get('title')}: {f.get('detail', '')[:200]}"
            for f in state.get("findings", [])[-20:]
        )
        or "(none yet)"
    )

    return [
        Send(
            "specialist",
            {
                "incident_id": state.get("incident_id", ""),
                "specialist": task["specialist"],
                "objective": task["objective"],
                "alert_text": alert_text,
                "prior_findings": prior,
                "round": int(state.get("round", 1)),
            },
        )
        for task in plan
    ]


def _after_critic(state: IncidentState) -> Literal["supervisor", "containment"]:
    settings = get_settings()
    if (
        state.get("needs_more_work")
        and int(state.get("round", 1)) < settings.max_investigation_rounds
    ):
        return "supervisor"
    return "containment"


def _after_containment(state: IncidentState) -> Literal["approval", "execute"]:
    needs = any(a.get("requires_approval") for a in state.get("containment_actions", []))
    return "approval" if needs else "execute"


def build_graph() -> StateGraph:
    g = StateGraph(IncidentState)

    g.add_node("intake", intake_node)
    g.add_node("supervisor", supervisor_node)
    g.add_node("specialist", specialist_node)
    g.add_node("critic", critic_node)
    g.add_node("containment", containment_node)
    g.add_node("approval", approval_node)
    g.add_node("execute", execute_node)
    g.add_node("report", report_node)

    g.add_edge(START, "intake")
    g.add_edge("intake", "supervisor")
    g.add_conditional_edges("supervisor", _dispatch, ["specialist", "critic"])
    g.add_edge("specialist", "critic")
    g.add_conditional_edges("critic", _after_critic, ["supervisor", "containment"])
    g.add_conditional_edges("containment", _after_containment, ["approval", "execute"])
    g.add_edge("approval", "execute")
    g.add_edge("execute", "report")
    g.add_edge("report", END)

    return g


# ── Compiled-graph lifecycle ─────────────────────────────────────────────────
# The checkpointer owns a connection pool, so the compiled graph is created once
# at startup and torn down with the app.

_compiled: Any = None
_checkpointer_cm: Any = None


async def init_graph() -> Any:
    """Compile the graph against a Postgres checkpointer. Idempotent."""
    global _compiled, _checkpointer_cm
    if _compiled is not None:
        return _compiled

    settings = get_settings()
    from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

    _checkpointer_cm = AsyncPostgresSaver.from_conn_string(settings.database_url)
    checkpointer = await _checkpointer_cm.__aenter__()
    await checkpointer.setup()

    _compiled = build_graph().compile(checkpointer=checkpointer)
    log.info("graph.compiled", checkpointer="postgres")
    return _compiled


async def init_graph_in_memory() -> Any:
    """Volatile checkpointer — tests and `make demo` only. State dies with the process."""
    global _compiled
    from langgraph.checkpoint.memory import MemorySaver

    _compiled = build_graph().compile(checkpointer=MemorySaver())
    log.info("graph.compiled", checkpointer="memory")
    return _compiled


def get_graph() -> Any:
    if _compiled is None:
        raise RuntimeError("Graph not initialised — call init_graph() during startup")
    return _compiled


async def close_graph() -> None:
    global _compiled, _checkpointer_cm
    if _checkpointer_cm is not None:
        await _checkpointer_cm.__aexit__(None, None, None)
        _checkpointer_cm = None
    _compiled = None
