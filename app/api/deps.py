"""Request authentication."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, status

from app.config import get_settings
from app.observability import get_logger

log = get_logger(__name__)


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """Guard the /v1 surface with a shared key, compared in constant time."""
    settings = get_settings()

    if not settings.api_key:
        # Refuse to serve an unauthenticated control plane rather than silently
        # allowing everything.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API_KEY is not configured on the server",
        )
    if not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key):
        log.warning("api.auth_rejected", supplied=bool(x_api_key))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing X-API-Key"
        )


async def require_webhook_token(authorization: str | None = Header(default=None)) -> None:
    """Guard inbound webhooks (n8n, SIEM) with a bearer token."""
    settings = get_settings()
    expected = settings.n8n_webhook_token or settings.api_key

    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="No webhook token configured on the server",
        )
    supplied = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization.split(" ", 1)[1].strip()

    if not supplied or not hmac.compare_digest(supplied, expected):
        log.warning("webhook.auth_rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing bearer token"
        )
