"""Containment planning, human approval gate, and action execution."""

from __future__ import annotations

from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.types import interrupt
from pydantic import BaseModel, Field, field_validator

from app.config import get_settings, severity_at_least
from app.graph import llm, prompts
from app.graph.llm import coerce_json_list
from app.graph.nodes.intake import now_iso
from app.graph.state import IncidentState
from app.observability import TOOL_CALLS, concise_error, get_logger
from app.slack import progress
from app.tools.n8n import call_n8n_webhook

log = get_logger(__name__)


class ProposedAction(BaseModel):
    action: str = Field(description="e.g. isolate_host, disable_account, block_ip, hunt_query")
    target: str = Field(description="The host, account, address or scope acted on")
    justification: str
    reversible: bool = True
    risk: str = Field(default="medium", description="low | medium | high")
    tool: str = Field(default="", description="n8n tool name that performs this, if any")
    tool_args: dict[str, Any] = Field(default_factory=dict)


class ContainmentPlan(BaseModel):
    actions: list[ProposedAction] = Field(default_factory=list)
    reasoning: str = ""

    _coerce = field_validator("actions", mode="before")(coerce_json_list)


async def containment_node(state: IncidentState) -> dict[str, Any]:
    settings = get_settings()

    if state.get("verdict") == "false_positive":
        return {
            "containment_actions": [],
            "timeline": [
                {
                    "at": now_iso(),
                    "actor": "containment_planner",
                    "event": "No actions proposed — verdict is false positive",
                }
            ],
        }

    findings = state.get("findings", [])
    available = [t["name"] for t in settings.parsed_n8n_tools()] if settings.n8n_enabled else []

    context = [
        f"VERDICT: {state.get('verdict')} at {state.get('severity')} severity",
        f"SUMMARY: {state.get('summary', '')}",
        "",
        "FINDINGS:",
        "\n".join(
            f"- [{f.get('severity')}] {f.get('title')}: {f.get('detail', '')[:300]}"
            for f in findings
        )
        or "(none)",
        "",
        f"ACTION TOOLS AVAILABLE: {', '.join(available) or 'none — propose manual actions only'}",
    ]

    try:
        plan = await llm.structured(
            "supervisor",
            ContainmentPlan,
            [SystemMessage(content=prompts.CONTAINMENT), HumanMessage(content="\n".join(context))],
        )
    except Exception as exc:
        log.error("containment.failed", error=str(exc))
        return {
            "containment_actions": [],
            "errors": [f"containment_planner: {concise_error(exc)}"],
            "timeline": [
                {
                    "at": now_iso(),
                    "actor": "containment_planner",
                    "event": f"Planning failed: {concise_error(exc)}",
                }
            ],
        }

    actions = []
    for a in plan.actions:
        d = a.model_dump()
        # Approval policy is enforced here, not by the model: anything at or above
        # the configured severity floor needs a human, as does anything irreversible.
        d["requires_approval"] = bool(
            settings.require_approval_for_containment
            and (
                not a.reversible
                or a.risk == "high"
                or severity_at_least(
                    str(state.get("severity", "informational")),
                    settings.auto_approve_severity_below,
                )
            )
        )
        actions.append(d)

    # The bot's posture on this incident can widen what runs unattended. Read it
    # from the record rather than from graph state: someone may have moved the
    # incident to responder mode while this very run was in flight, and the
    # whole point of doing so is that it takes effect now.
    incident_id = str(state.get("incident_id", ""))
    actions, autonomous, gated = await _apply_mode(incident_id, actions)

    log.info(
        "containment.planned",
        incident_id=incident_id,
        actions=len(actions),
        needing_approval=len(gated),
        autonomous=len(autonomous),
    )
    await progress.containment_planned(incident_id, actions)

    events = [
        {
            "at": now_iso(),
            "actor": "containment_planner",
            "event": f"Proposed {len(actions)} containment action(s)",
        }
    ]
    if autonomous:
        # Autonomous execution has to leave a mark before it happens, not only
        # in the executed list afterwards — otherwise the record cannot show
        # that a human was never asked.
        events.append(
            {
                "at": now_iso(),
                "actor": "containment_planner",
                "event": (
                    f"Mode allows {len(autonomous)} action(s) to run without approval: "
                    f"{', '.join(autonomous)}"
                ),
            }
        )

    return {"containment_actions": actions, "timeline": events}


async def _apply_mode(
    incident_id: str, actions: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[str], list[str]]:
    """Re-gate the plan under the incident's autonomy mode. Never raises."""
    from app.services import modes

    settings = get_settings()
    try:
        from app.services import incidents

        record = await incidents.get_incident(incident_id) if incident_id else None
    except Exception as exc:  # noqa: BLE001 — an unreadable mode must not lose the plan
        log.warning("containment.mode_read_failed", incident_id=incident_id, error=str(exc))
        record = None

    # No record, no mode, no autonomy. Failing closed is the only safe direction
    # for a function whose job is deciding what may run unsupervised.
    mode = modes.get((record or {}).get("mode") or settings.ir_mode_default)
    return modes.apply_to_actions(actions, mode, settings.ir_autonomous_max_risk)


async def approval_node(state: IncidentState) -> dict[str, Any]:
    """Pause the graph and wait for a human.

    `interrupt` persists the payload to the checkpoint and stops the run. The API
    resumes it with `Command(resume={...})` when an analyst clicks approve/reject
    in Slack or the dashboard — possibly days later.
    """
    actions = [a for a in state.get("containment_actions", []) if a.get("requires_approval")]

    decision = interrupt(
        {
            "kind": "containment_approval",
            "incident_id": state.get("incident_id"),
            "severity": state.get("severity"),
            "verdict": state.get("verdict"),
            "summary": state.get("summary"),
            "actions": actions,
        }
    )

    approved: list[str] = []
    if isinstance(decision, dict):
        if decision.get("approved_all"):
            approved = [a["action"] for a in actions]
        else:
            approved = list(decision.get("approved_actions", []))
        approver = decision.get("approver", "unknown")
        note = decision.get("note", "")
    else:  # a bare truthy resume value means "approve everything"
        approved = [a["action"] for a in actions] if decision else []
        approver, note = "unknown", ""

    log.info(
        "approval.received",
        incident_id=state.get("incident_id"),
        approver=approver,
        approved=len(approved),
        proposed=len(actions),
    )

    return {
        "approval": {
            "approver": approver,
            "approved_actions": approved,
            "note": note,
            "at": now_iso(),
        },
        "status": "running",
        "timeline": [
            {
                "at": now_iso(),
                "actor": f"human:{approver}",
                "event": f"Approved {len(approved)} of {len(actions)} action(s)"
                + (f" — {note}" if note else ""),
            }
        ],
    }


async def execute_node(state: IncidentState) -> dict[str, Any]:
    """Run the actions that are cleared to run — auto-approved or human-approved."""
    approval = state.get("approval", {}) or {}
    approved_names = set(approval.get("approved_actions", []))

    runnable = [
        a
        for a in state.get("containment_actions", [])
        if a.get("tool") and (not a.get("requires_approval") or a["action"] in approved_names)
    ]
    if not runnable:
        return {
            "timeline": [{"at": now_iso(), "actor": "executor", "event": "No actions executed"}]
        }

    settings = get_settings()
    tool_paths = {t["name"]: t["path"] for t in settings.parsed_n8n_tools()}
    executed: list[dict[str, Any]] = []
    errors: list[str] = []

    for action in runnable:
        tool = action["tool"]
        path = tool_paths.get(tool)
        if not path:
            errors.append(f"executor: no n8n workflow registered for tool '{tool}'")
            continue
        try:
            result = await call_n8n_webhook(
                path,
                {
                    "incident_id": state.get("incident_id"),
                    "input": {
                        "action": action["action"],
                        "target": action["target"],
                        **action.get("tool_args", {}),
                    },
                },
            )
            TOOL_CALLS.labels(tool=tool, outcome="ok").inc()
            executed.append({**action, "result": result.get("body"), "at": now_iso()})
        except Exception as exc:
            TOOL_CALLS.labels(tool=tool, outcome="error").inc()
            log.error("execute.action_failed", action=action["action"], error=str(exc))
            errors.append(
                f"executor: {action['action']} on {action['target']} failed: {concise_error(exc)}"
            )

    await progress.executed(str(state.get("incident_id", "")), len(executed), len(errors))

    return {
        "executed_actions": executed,
        "errors": errors,
        "timeline": [
            {
                "at": now_iso(),
                "actor": "executor",
                "event": f"Executed {len(executed)} action(s), {len(errors)} failure(s)",
            }
        ],
    }
