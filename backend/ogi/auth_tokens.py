"""Local-auth session tokens: HMAC-signed, stateless, cookie + Bearer.

A local session token is ``base64url(user_id|expiry)`` followed by an HMAC-SHA256
signature. It is delivered as an HttpOnly cookie (``ogi_session``) and accepted
identically as an ``Authorization: Bearer <token>`` header, so API clients and
the browser share one mechanism.

If ``OGI_SESSION_SECRET`` is unset, an ephemeral per-process key is used and
sessions do not survive a backend restart — set it for durable logins.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import time
from uuid import UUID

from ogi.config import settings

logger = logging.getLogger(__name__)

SESSION_COOKIE_NAME = "ogi_session"

_ephemeral_key: bytes | None = None


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64d(enc: str) -> bytes:
    pad = "=" * (-len(enc) % 4)
    return base64.urlsafe_b64decode(enc + pad)


def _secret() -> bytes:
    global _ephemeral_key
    if settings.session_secret:
        return settings.session_secret.encode("utf-8")
    if _ephemeral_key is None:
        _ephemeral_key = secrets.token_bytes(32)
        logger.warning(
            "OGI_SESSION_SECRET is unset — local auth sessions are ephemeral "
            "and will not survive a backend restart."
        )
    return _ephemeral_key


def _sign(payload: bytes) -> bytes:
    return hmac.new(_secret(), payload, hashlib.sha256).digest()


def issue_session_token(user_id: UUID, ttl_seconds: int | None = None) -> str:
    ttl = ttl_seconds if ttl_seconds is not None else settings.session_ttl_seconds
    expiry = int(time.time()) + ttl
    payload = f"{user_id}|{expiry}".encode("utf-8")
    return f"{_b64e(payload)}.{_b64e(_sign(payload))}"


def verify_session_token(token: str) -> UUID | None:
    """Return the user_id if the token is valid and unexpired, else None."""
    try:
        payload_b64, sig_b64 = token.split(".", 1)
        payload = _b64d(payload_b64)
        sig = _b64d(sig_b64)
    except (ValueError, Exception):  # noqa: BLE001
        return None

    if not hmac.compare_digest(_sign(payload), sig):
        return None

    try:
        user_id_str, expiry_str = payload.decode("utf-8").split("|", 1)
        expiry = int(expiry_str)
    except (ValueError, UnicodeDecodeError):
        return None

    if expiry < int(time.time()):
        return None

    try:
        return UUID(user_id_str)
    except ValueError:
        return None
