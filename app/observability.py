"""Structured logging + Prometheus metrics."""

from __future__ import annotations

import logging
import os
import sys

import structlog
from prometheus_client import Counter, Gauge, Histogram

from app.config import get_settings

# ── Metrics ──────────────────────────────────────────────────────────────────
RUNS_STARTED = Counter("agenticir_runs_started_total", "Investigations started", ["source"])
RUNS_COMPLETED = Counter(
    "agenticir_runs_completed_total", "Investigations finished", ["status", "severity"]
)
NODE_DURATION = Histogram(
    "agenticir_node_duration_seconds",
    "Per-node execution time",
    ["node"],
    buckets=(0.5, 1, 2.5, 5, 10, 30, 60, 120, 300),
)
LLM_CALLS = Counter("agenticir_llm_calls_total", "LLM invocations", ["role", "outcome"])
TOOL_CALLS = Counter("agenticir_tool_calls_total", "Tool invocations", ["tool", "outcome"])

# Counters answer "how much has run"; these answer "what is running right now",
# which is the question asked when an investigation feels slow.
ACTIVE_RUNS = Gauge("agenticir_active_runs", "Investigations executing right now")
ACTIVE_SPECIALISTS = Gauge(
    "agenticir_active_specialists", "Specialist agents executing right now", ["specialist"]
)

# ── Slack channel polling ──
POLL_CYCLES = Counter("agenticir_slack_poll_cycles_total", "Poll sweeps", ["outcome"])
POLL_MESSAGES = Counter(
    "agenticir_slack_poll_messages_total", "Channel messages triaged", ["disposition"]
)

# What the caretaker did between runs. On a long incident this is most of what
# the platform does, and none of it shows up in the run counters.
UPKEEP_ACTIONS = Counter(
    "agenticir_upkeep_actions_total", "Between-run caretaker actions", ["action"]
)


def configure_logging() -> None:
    settings = get_settings()

    processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if settings.log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()))

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelName(settings.log_level.upper())
        ),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=settings.log_level.upper())
    # These are chatty and rarely useful at INFO.
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def configure_tracing() -> None:
    """LangSmith reads plain env vars; mirror our settings onto them."""
    settings = get_settings()
    if not settings.langsmith_tracing or not settings.langsmith_api_key:
        os.environ["LANGSMITH_TRACING"] = "false"
        return
    os.environ["LANGSMITH_TRACING"] = "true"
    os.environ["LANGSMITH_ENDPOINT"] = settings.langsmith_endpoint
    os.environ["LANGSMITH_API_KEY"] = settings.langsmith_api_key
    os.environ["LANGSMITH_PROJECT"] = settings.langsmith_project


def get_logger(name: str = "agenticir") -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)


_ERROR_MAX = 240


def concise_error(exc: BaseException, limit: int = _ERROR_MAX) -> str:
    """Compress a provider exception into one readable line.

    LLM SDKs raise with the provider's whole JSON body embedded in the message.
    Recorded verbatim on every failing node, a single outage turns the incident
    report into several screens of duplicated JSON. Pull out the human-readable
    message where the body has one, and cap the rest.
    """
    text = str(exc).strip()
    kind = type(exc).__name__

    # Most providers nest the useful sentence at {"error": {"message": ...}}.
    # The body may arrive as JSON or as a Python repr, so accept either quoting.
    for key in ('"message"', "'message'"):
        start = text.find(key)
        if start == -1:
            continue
        rest = text[start + len(key) :].lstrip(" :")
        if rest[:1] not in {"'", '"'}:
            continue
        quote = rest[0]
        end = rest.find(quote, 1)
        if end > 1:
            text = rest[1:end]
            break

    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return f"{kind}: {text}" if text else kind
