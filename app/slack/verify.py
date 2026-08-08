"""Slack request signature verification.

Slack signs every request; we reject anything unsigned, stale, or mismatched.
This is the only thing standing between a public URL and arbitrary command
injection into the IR pipeline, so it fails closed.
"""

from __future__ import annotations

import hashlib
import hmac
import time

from app.config import get_settings
from app.observability import get_logger

log = get_logger(__name__)

# Slack's own guidance: reject anything older than five minutes to blunt replays.
MAX_SKEW_SECONDS = 60 * 5


def verify_slack_request(body: bytes, timestamp: str | None, signature: str | None) -> bool:
    settings = get_settings()

    if not settings.slack_signing_secret:
        log.error("slack.verify_no_secret")
        return False
    if not timestamp or not signature:
        log.warning("slack.verify_missing_headers")
        return False

    try:
        sent_at = int(timestamp)
    except ValueError:
        log.warning("slack.verify_bad_timestamp", timestamp=timestamp)
        return False

    if abs(time.time() - sent_at) > MAX_SKEW_SECONDS:
        log.warning("slack.verify_stale", skew=time.time() - sent_at)
        return False

    basestring = b"v0:" + timestamp.encode() + b":" + body
    expected = (
        "v0="
        + hmac.new(settings.slack_signing_secret.encode(), basestring, hashlib.sha256).hexdigest()
    )

    if not hmac.compare_digest(expected, signature):
        log.warning("slack.verify_signature_mismatch")
        return False
    return True
