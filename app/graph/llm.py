"""Model factory. One place to swap providers or downgrade a role to a cheap model."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any, Literal, TypeVar

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import BaseMessage
from pydantic import BaseModel

from app.config import get_settings
from app.observability import LLM_CALLS, get_logger

log = get_logger(__name__)

Role = Literal["supervisor", "specialist", "critic"]
T = TypeVar("T", bound=BaseModel)


def _model_name(role: Role) -> str:
    s = get_settings()
    return {
        "supervisor": s.llm_model_supervisor,
        "specialist": s.llm_model_specialist,
        "critic": s.llm_model_critic,
    }[role]


@lru_cache(maxsize=16)
def get_llm(role: Role = "specialist") -> BaseChatModel:
    """Build (and memoise) the chat model for a role."""
    s = get_settings()
    model = _model_name(role)
    common: dict[str, Any] = {
        "temperature": s.llm_temperature,
        "timeout": s.llm_timeout_seconds,
    }

    if s.llm_provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        if not s.anthropic_api_key:
            raise RuntimeError("LLM_PROVIDER=anthropic but ANTHROPIC_API_KEY is unset")
        return ChatAnthropic(
            model=model,
            api_key=s.anthropic_api_key,
            max_tokens=s.llm_max_tokens,
            max_retries=3,
            **common,
        )

    if s.llm_provider == "openrouter":
        from langchain_openai import ChatOpenAI

        if not s.openrouter_api_key:
            raise RuntimeError(
                "LLM_PROVIDER=openrouter but OPENROUTER_API_KEY (or OPENROUTER_API_TOKEN) is unset"
            )
        return ChatOpenAI(
            model=model,
            api_key=s.openrouter_api_key,
            base_url=s.openrouter_base_url,
            max_tokens=s.llm_max_tokens,
            max_retries=3,
            # OpenRouter uses these for attribution on its dashboards.
            default_headers={
                "HTTP-Referer": s.public_base_url,
                "X-Title": s.openrouter_app_name,
            },
            **common,
        )

    if s.llm_provider == "openai":
        from langchain_openai import ChatOpenAI

        if not s.openai_api_key:
            raise RuntimeError("LLM_PROVIDER=openai but OPENAI_API_KEY is unset")
        return ChatOpenAI(
            model=model,
            api_key=s.openai_api_key,
            base_url=s.openai_base_url or None,
            max_tokens=s.llm_max_tokens,
            max_retries=3,
            **common,
        )

    from langchain_ollama import ChatOllama

    return ChatOllama(model=model, base_url=s.ollama_base_url, **common)


def _structured_kwargs() -> dict[str, Any]:
    """Pin the structured-output strategy where the default is a bad bet.

    langchain-openai increasingly prefers native `json_schema` strict mode, which
    third-party OpenAI-compatible gateways often do not implement — and when they
    don't, the failure is an opaque 400 rather than a fallback. Tool calling is
    supported far more widely, so force it for gateway providers.
    """
    if get_settings().llm_provider in {"openrouter"} or (
        get_settings().llm_provider == "openai" and get_settings().openai_base_url
    ):
        return {"method": "function_calling"}
    return {}


async def structured(
    role: Role,
    schema: type[T],
    messages: list[BaseMessage],
) -> T:
    """Invoke a model and coerce the reply into `schema`.

    Raises on failure — callers decide whether that degrades the node or the run.
    """
    llm = get_llm(role).with_structured_output(schema, **_structured_kwargs())
    try:
        result = await llm.ainvoke(messages)
        LLM_CALLS.labels(role=role, outcome="ok").inc()
        return result  # type: ignore[return-value]
    except Exception as exc:
        LLM_CALLS.labels(role=role, outcome="error").inc()
        log.error("llm.structured_failed", role=role, schema=schema.__name__, error=str(exc))
        raise


def coerce_json_list(value: Any) -> Any:
    """Accept a JSON-encoded list where a list was requested.

    Observed in production against OpenRouter: a model returned `findings` as a
    JSON *string* rather than an array, and pydantic rejected the whole report —
    losing an entire specialist's work over a formatting quirk. Providers differ
    here, so parse leniently and let validation judge the parsed content.
    """
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return value
        return parsed if isinstance(parsed, list) else value
    return value


async def text(role: Role, messages: list[BaseMessage]) -> str:
    llm = get_llm(role)
    try:
        result = await llm.ainvoke(messages)
        LLM_CALLS.labels(role=role, outcome="ok").inc()
        content = result.content
        if isinstance(content, list):  # Anthropic content blocks
            return "".join(
                block.get("text", "") for block in content if isinstance(block, dict)
            ).strip()
        return str(content).strip()
    except Exception as exc:
        LLM_CALLS.labels(role=role, outcome="error").inc()
        log.error("llm.text_failed", role=role, error=str(exc))
        raise
