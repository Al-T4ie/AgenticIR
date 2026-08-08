"""Provider errors must stay readable on the incident record.

Written after a real OpenRouter outage: every node failed, and each one recorded
the provider's full JSON body, turning the report into screens of duplicated
noise. The report is what an analyst reads at 3am.
"""

from __future__ import annotations

import pytest

from app.observability import concise_error

# The exact shape OpenRouter returns, as seen in a live run.
OPENROUTER_402 = (
    "Error code: 402 - {'error': {'message': 'Insufficient credits. Add more using "
    "https://openrouter.ai/settings/credits', 'code': 402, 'metadata': "
    "{'limit_source': 'openrouter_credits', 'remedy_hint': 'Add credits at "
    "https://openrouter.ai/settings/credits, or lower max_tokens / prompt size to "
    "fit your remaining balance.'}}}"
)


def test_extracts_the_human_message_from_a_provider_body():
    out = concise_error(RuntimeError(OPENROUTER_402))
    assert "Insufficient credits" in out
    assert out.startswith("RuntimeError: ")
    # The metadata blob is what made the original report unreadable.
    assert "remedy_hint" not in out
    assert "limit_source" not in out


def test_result_is_short_enough_to_read():
    out = concise_error(RuntimeError(OPENROUTER_402))
    assert len(out) < 300, f"still too long to sit in a Slack block: {len(out)}"


def test_plain_exceptions_pass_through_with_their_type():
    assert concise_error(ValueError("bad indicator")) == "ValueError: bad indicator"


def test_an_empty_message_still_names_the_type():
    assert concise_error(TimeoutError()) == "TimeoutError"


def test_long_messages_are_truncated_with_an_ellipsis():
    out = concise_error(RuntimeError("x" * 5000))
    assert len(out) <= 240 + len("RuntimeError: ")
    assert out.endswith("…")


def test_newlines_are_collapsed():
    """Multi-line tracebacks in a message break Slack block formatting."""
    out = concise_error(RuntimeError("line one\n\n   line two\tline three"))
    assert "\n" not in out
    assert out == "RuntimeError: line one line two line three"


def test_double_quoted_json_bodies_also_parse():
    out = concise_error(RuntimeError('{"error": {"message": "rate limit exceeded"}}'))
    assert out == "RuntimeError: rate limit exceeded"


@pytest.mark.parametrize(
    "text",
    ['{"error": {"message":}}', '"message"', '"message": ', "no message key here"],
)
def test_malformed_bodies_do_not_raise(text: str):
    """A parser for error strings must never itself become the error."""
    assert concise_error(RuntimeError(text)).startswith("RuntimeError")


def test_custom_limit_is_honoured():
    out = concise_error(RuntimeError("y" * 500), limit=50)
    assert len(out) <= 50 + len("RuntimeError: ")
