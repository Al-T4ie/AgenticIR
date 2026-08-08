"""Central settings. Everything is env-driven so the same image runs locally and on Coolify."""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Severity = Literal["informational", "low", "medium", "high", "critical"]
SEVERITY_ORDER: list[str] = ["informational", "low", "medium", "high", "critical"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", case_sensitive=False
    )

    # ── Core ──
    app_env: Literal["development", "production"] = "development"
    log_level: str = "INFO"
    log_format: Literal["console", "json"] = "console"
    public_base_url: str = "http://localhost:8000"
    api_key: str = "dev-local-key-change-me"
    cors_origins: str = "*"

    # ── LLM ──
    llm_provider: Literal["anthropic", "openai", "openrouter", "ollama"] = "anthropic"
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    # Lets the `openai` provider talk to any OpenAI-compatible gateway
    # (LiteLLM, vLLM, a corporate proxy). Empty means api.openai.com.
    openai_base_url: str = ""
    ollama_base_url: str = "http://ollama:11434"

    # OpenRouter is OpenAI-compatible but wants its own key and base URL, and
    # gives better rankings/attribution when the app identifies itself.
    # OPENROUTER_API_TOKEN is accepted as an alias for the key.
    openrouter_api_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "openrouter_api_key",
            "OPENROUTER_API_KEY",
            "openrouter_api_token",
            "OPENROUTER_API_TOKEN",
        ),
    )
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_app_name: str = "AgenticIR"

    llm_model_supervisor: str = "claude-sonnet-5"
    llm_model_specialist: str = "claude-haiku-4-5-20251001"
    llm_model_critic: str = "claude-opus-5"
    llm_temperature: float = 0.0
    llm_max_tokens: int = 4096
    llm_timeout_seconds: int = 120

    # ── Agent behaviour ──
    max_investigation_rounds: int = 3
    max_parallel_specialists: int = 5
    require_approval_for_containment: bool = True
    auto_approve_severity_below: str = "low"

    # ── Persistence ──
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "agenticir"
    postgres_user: str = "agenticir"
    postgres_password: str = "agenticir-local-dev"
    redis_url: str = "redis://redis:6379/0"

    # ── Slack ──
    slack_enabled: bool = False
    slack_bot_token: str = ""
    slack_signing_secret: str = ""
    slack_default_channel: str = "#incident-response"

    # ── n8n ──
    n8n_enabled: bool = False
    n8n_base_url: str = "http://n8n:5678"
    n8n_webhook_token: str = ""
    n8n_tools: str = ""

    # ── Observability ──
    langsmith_tracing: bool = False
    langsmith_endpoint: str = "https://api.smith.langchain.com"
    langsmith_api_key: str = ""
    langsmith_project: str = "agentic-ir"

    # Compose interpolation writes an empty string for an unset variable
    # (`FOO: ${FOO}` with no FOO), which would otherwise fail int validation.
    # Fall back to the field's declared default instead of exploding at startup.
    @field_validator(
        "postgres_port",
        "llm_max_tokens",
        "llm_timeout_seconds",
        "max_investigation_rounds",
        "max_parallel_specialists",
        mode="before",
    )
    @classmethod
    def _blank_to_default(cls, v: object, info: ValidationInfo) -> object:
        if v != "" or info.field_name is None:
            return v
        return cls.model_fields[info.field_name].default

    @property
    def database_url(self) -> str:
        """psycopg3 (sync) DSN — what the LangGraph Postgres checkpointer wants."""
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def async_database_url(self) -> str:
        """SQLAlchemy asyncpg DSN for the incident store."""
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    def parsed_n8n_tools(self) -> list[dict[str, str]]:
        """`name:path:description` triples -> tool descriptors."""
        tools: list[dict[str, str]] = []
        for raw in self.n8n_tools.split(","):
            raw = raw.strip()
            if not raw:
                continue
            parts = raw.split(":", 2)
            if len(parts) < 2:
                continue
            tools.append(
                {
                    "name": parts[0].strip(),
                    "path": parts[1].strip(),
                    "description": parts[2].strip() if len(parts) > 2 else parts[0].strip(),
                }
            )
        return tools


@lru_cache
def get_settings() -> Settings:
    return Settings()


def severity_at_least(value: str, threshold: str) -> bool:
    """True when `value` is at or above `threshold` on the severity ladder."""
    if threshold == "never":
        return True
    try:
        return SEVERITY_ORDER.index(value) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return True
