"""Provider wiring: base URLs, key aliases, and structured-output strategy."""

from __future__ import annotations

import pytest

from app.config import Settings


# ── Key resolution ───────────────────────────────────────────────────────────
def test_openrouter_key_accepts_either_env_name(monkeypatch: pytest.MonkeyPatch):
    """The docs say OPENROUTER_API_KEY; people paste OPENROUTER_API_TOKEN. Take both."""
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.setenv("OPENROUTER_API_TOKEN", "sk-or-v1-from-token-name")
    assert Settings().openrouter_api_key == "sk-or-v1-from-token-name"

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-v1-from-key-name")
    assert Settings().openrouter_api_key == "sk-or-v1-from-key-name"


def test_openrouter_defaults_to_the_public_gateway():
    assert Settings().openrouter_base_url == "https://openrouter.ai/api/v1"


def test_openai_base_url_is_empty_by_default():
    """Empty means api.openai.com — we must not send an empty string as a URL."""
    assert Settings().openai_base_url == ""


# ── Model construction ───────────────────────────────────────────────────────
def _fresh_llm():
    """get_llm is lru_cached and settings are lru_cached; clear both."""
    from app.config import get_settings
    from app.graph import llm as llm_module

    get_settings.cache_clear()
    llm_module.get_llm.cache_clear()
    return llm_module


def test_openrouter_builds_a_client_pointed_at_the_gateway(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_TOKEN", "sk-or-v1-test")
    monkeypatch.setenv("LLM_MODEL_SPECIALIST", "anthropic/claude-3.5-haiku")

    llm_module = _fresh_llm()
    model = llm_module.get_llm("specialist")

    assert model.model_name == "anthropic/claude-3.5-haiku"
    assert str(model.openai_api_base).rstrip("/") == "https://openrouter.ai/api/v1"

    _fresh_llm()


def test_openrouter_without_a_key_fails_loudly(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_TOKEN", raising=False)

    llm_module = _fresh_llm()
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        llm_module.get_llm("specialist")

    _fresh_llm()


def test_openai_honours_a_custom_gateway(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://litellm.internal/v1")

    llm_module = _fresh_llm()
    model = llm_module.get_llm("supervisor")
    assert str(model.openai_api_base).rstrip("/") == "https://litellm.internal/v1"

    _fresh_llm()


# ── Structured-output strategy ───────────────────────────────────────────────
def test_gateways_force_function_calling(monkeypatch: pytest.MonkeyPatch):
    """Native json_schema strict mode is not reliably implemented by gateways;
    an unsupported request fails as an opaque 400 rather than degrading."""
    monkeypatch.setenv("LLM_PROVIDER", "openrouter")
    monkeypatch.setenv("OPENROUTER_API_TOKEN", "sk-or-v1-test")

    llm_module = _fresh_llm()
    assert llm_module._structured_kwargs() == {"method": "function_calling"}

    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://litellm.internal/v1")
    llm_module = _fresh_llm()
    assert llm_module._structured_kwargs() == {"method": "function_calling"}

    _fresh_llm()


def test_first_party_providers_keep_the_default_strategy(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    llm_module = _fresh_llm()
    assert llm_module._structured_kwargs() == {}

    _fresh_llm()
