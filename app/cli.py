"""Operator CLI: run an investigation without Slack, n8n, or a database.

agentic-ir demo --question "suspicious powershell on FIN-WS-04"
agentic-ir demo --file alert.json
agentic-ir graph            # print the topology as mermaid
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from app.graph.builder import build_graph, init_graph_in_memory
from app.graph.state import new_state
from app.observability import configure_logging


async def _demo(alert: dict[str, Any], question: str, auto_approve: bool) -> int:
    from langgraph.types import Command

    graph = await init_graph_in_memory()
    config = {"configurable": {"thread_id": "cli-demo"}, "recursion_limit": 60}

    state = new_state(
        incident_id="INC-CLI-DEMO",
        thread_id="cli-demo",
        source="cli",
        alert=alert,
        question=question,
    )

    print("── Running investigation ─────────────────────────────────────────\n")
    await graph.ainvoke(state, config=config)

    snapshot = await graph.aget_state(config)
    pending = list(getattr(snapshot, "interrupts", None) or [])
    if pending:
        payload = getattr(pending[0], "value", pending[0])
        print("\n── Containment approval required ────────────────────────────────")
        for action in (payload or {}).get("actions", []):
            print(
                f"  • {action.get('action')} → {action.get('target')}  ({action.get('risk')} risk)"
            )
            print(f"    {action.get('justification', '')}")

        approve = auto_approve
        if not auto_approve and sys.stdin.isatty():
            # Blocking input is what we want here: this is an interactive CLI
            # prompt and there is nothing else for the event loop to do.
            approve = input("\nApprove all actions? [y/N] ").strip().lower() == "y"  # noqa: ASYNC250

        await graph.ainvoke(
            Command(
                resume={
                    "approved_all": approve,
                    "approved_actions": [a["action"] for a in (payload or {}).get("actions", [])]
                    if approve
                    else [],
                    "approver": "cli",
                }
            ),
            config=config,
        )
        snapshot = await graph.aget_state(config)

    final = dict(snapshot.values or {})
    print("\n── Report ────────────────────────────────────────────────────────\n")
    print(final.get("report") or final.get("summary") or "(no report produced)")
    print(
        f"\nVerdict: {final.get('verdict')} | Severity: {final.get('severity')} | "
        f"Findings: {len(final.get('findings', []))}"
    )
    if final.get("errors"):
        print("\nErrors:")
        for err in final["errors"]:
            print(f"  ! {err}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="agentic-ir", description="AgenticIR operator CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    demo = sub.add_parser("demo", help="Run one investigation locally (in-memory state)")
    demo.add_argument("--question", default="", help="Analyst question")
    demo.add_argument("--file", type=Path, help="Path to a JSON alert")
    demo.add_argument("--yes", action="store_true", help="Auto-approve containment")

    sub.add_parser("graph", help="Print the graph topology as mermaid")

    args = parser.parse_args()
    configure_logging()

    if args.command == "graph":
        print(build_graph().compile().get_graph().draw_mermaid())
        return 0

    alert: dict[str, Any] = {}
    if args.file:
        alert = json.loads(args.file.read_text())
    if not alert and not args.question:
        parser.error("provide --question or --file")

    return asyncio.run(_demo(alert, args.question, args.yes))


if __name__ == "__main__":
    raise SystemExit(main())
