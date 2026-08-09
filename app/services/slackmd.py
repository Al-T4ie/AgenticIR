"""Render Slack-flavoured markdown as HTML.

Reports are written for Slack, because that is where a responder reads them
mid-incident. On the dashboard the same text was shown verbatim inside a `pre`,
so `*inconclusive · high*` rendered with the asterisks and backticks visible —
which reads as a broken page rather than as emphasis.

This converts the small dialect the report prompt actually produces, and
nothing more. Everything is HTML-escaped *first*, so a report that quotes an
attacker's payload cannot inject markup into the page that renders it.
"""

from __future__ import annotations

import html
import re

# Slack's mrkdwn: single asterisks bold, single underscores italic, backticks
# code. Applied to already-escaped text, so the patterns can never span a tag.
_CODE = re.compile(r"`([^`\n]+)`")
_BOLD = re.compile(r"(?<![\w*])\*([^*\n]+)\*(?![\w*])")
_ITALIC = re.compile(r"(?<![\w_])_([^_\n]+)_(?![\w_])")
_BULLET = re.compile(r"^\s*(?:[•*\-–]|\d+[.)])\s+")


def to_html(text: str) -> str:
    """Convert a Slack-markdown report body into safe HTML."""
    if not text or not text.strip():
        return ""

    blocks: list[str] = []
    bullets: list[str] = []

    def flush() -> None:
        if bullets:
            blocks.append("<ul>" + "".join(f"<li>{b}</li>" for b in bullets) + "</ul>")
            bullets.clear()

    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            flush()
            continue
        # Escape before any markup is introduced — a payload quoted in a
        # finding must never become live HTML.
        escaped = html.escape(line.strip())
        escaped = _CODE.sub(r"<code>\1</code>", escaped)
        escaped = _BOLD.sub(r"<strong>\1</strong>", escaped)
        escaped = _ITALIC.sub(r"<em>\1</em>", escaped)

        if _BULLET.match(line.strip()):
            bullets.append(_BULLET.sub("", escaped, count=1))
        else:
            flush()
            blocks.append(f"<p>{escaped}</p>")

    flush()
    return "".join(blocks)
