"""n8n bridge: turns configured n8n webhooks into LangChain tools.

Contract with n8n
-----------------
Agent  -> POST {N8N_BASE_URL}/webhook/{path}
          Authorization: Bearer {N8N_WEBHOOK_TOKEN}
          {"incident_id": "...", "input": {...}}
n8n    -> 200 with any JSON body. Whatever comes back is handed to the model.

Failures never raise into the graph — the tool returns an error string so the
agent can reason about the failure instead of the run dying.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from langchain_core.tools import StructuredTool
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from app.config import get_settings
from app.observability import TOOL_CALLS, get_logger

log = get_logger(__name__)

_TIMEOUT = httpx.Timeout(60.0, connect=10.0)


@retry(
    retry=retry_if_exception_type((httpx.TransportError, httpx.HTTPStatusError)),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    reraise=True,
)
async def call_n8n_webhook(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    settings = get_settings()
    url = f"{settings.n8n_base_url.rstrip('/')}/webhook/{path.lstrip('/')}"
    headers = {"Content-Type": "application/json"}
    if settings.n8n_webhook_token:
        headers["Authorization"] = f"Bearer {settings.n8n_webhook_token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        if not resp.content:
            return {"ok": True, "body": None}
        try:
            return {"ok": True, "body": resp.json()}
        except json.JSONDecodeError:
            return {"ok": True, "body": resp.text}


def _make_tool(name: str, path: str, description: str) -> StructuredTool:
    async def _run(query: str, incident_id: str = "") -> str:
        try:
            result = await call_n8n_webhook(
                path, {"incident_id": incident_id, "input": {"query": query}}
            )
            TOOL_CALLS.labels(tool=name, outcome="ok").inc()
            return json.dumps(result.get("body"), default=str)[:8000]
        except Exception as exc:
            TOOL_CALLS.labels(tool=name, outcome="error").inc()
            log.warning("n8n.tool_failed", tool=name, path=path, error=str(exc))
            return f"ERROR: n8n workflow '{name}' failed: {exc}. Do not retry; note the gap."

    return StructuredTool.from_function(
        coroutine=_run,
        name=name,
        description=(
            f"{description}\n\nArgs: query (what to look up), "
            f"incident_id (current incident, for audit correlation)."
        ),
    )


def n8n_tools() -> list[StructuredTool]:
    """Tools declared via the N8N_TOOLS env var. Empty when n8n is disabled."""
    settings = get_settings()
    if not settings.n8n_enabled:
        return []
    tools = [
        _make_tool(t["name"], t["path"], t["description"]) for t in settings.parsed_n8n_tools()
    ]
    log.info("n8n.tools_registered", count=len(tools), names=[t.name for t in tools])
    return tools
