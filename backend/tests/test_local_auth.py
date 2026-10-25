"""Tests for the fork's local passkey-first auth.

Covers the mode dispatch, HMAC session tokens, the first-run bootstrap, the
admin invite lifecycle, the password fallback, and the passkey begin endpoints
(the cryptographic completion paths need a real authenticator and are exercised
manually in a browser).
"""
from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("OGI_DB_PATH", ":memory:")
os.environ.setdefault("OGI_USE_SQLITE", "true")
os.environ.setdefault("OGI_SUPABASE_URL", "")
os.environ.setdefault("OGI_SUPABASE_ANON_KEY", "")
os.environ.setdefault("OGI_TELEMETRY_ENABLED", "false")

from ogi.main import app  # noqa: E402
from ogi.config import settings  # noqa: E402
from ogi.auth_tokens import issue_session_token, verify_session_token  # noqa: E402


@pytest.fixture
def local_auth(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    monkeypatch.setattr(settings, "webauthn_rpid", "test.local")
    monkeypatch.setattr(settings, "public_origin", "http://test")
    monkeypatch.setattr(settings, "extra_allowed_origins", "")
    monkeypatch.setattr(settings, "setup_token", "s3cret-setup-token")
    monkeypatch.setattr(settings, "admin_emails", "admin@example.com")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret")
    monkeypatch.setattr(settings, "password_auth_enabled", False)
    yield settings


@pytest.fixture
async def client(local_auth):
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        async with app.router.lifespan_context(app):
            yield c


# --------------------------------------------------------------------------- #
# session tokens
# --------------------------------------------------------------------------- #

def test_session_token_roundtrip(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "session_secret", "abc")
    uid = uuid4()
    token = issue_session_token(uid)
    assert verify_session_token(token) == uid


def test_session_token_rejects_tamper(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "session_secret", "abc")
    token = issue_session_token(uuid4())
    forged = token[:-1] + ("A" if token[-1] != "A" else "B")
    assert verify_session_token(forged) is None


def test_session_token_rejects_expired(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "session_secret", "abc")
    token = issue_session_token(uuid4(), ttl_seconds=-10)
    assert verify_session_token(token) is None


def test_session_token_rejects_wrong_secret(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "session_secret", "abc")
    token = issue_session_token(uuid4())
    monkeypatch.setattr(settings, "session_secret", "other")
    assert verify_session_token(token) is None


# --------------------------------------------------------------------------- #
# mode dispatch
# --------------------------------------------------------------------------- #

def test_auth_mode_defaults_to_anonymous(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "supabase_url", "")
    monkeypatch.setattr(settings, "supabase_anon_key", "")
    monkeypatch.setattr(settings, "local_auth_enabled", False)
    assert settings.auth_mode == "anonymous"


def test_auth_mode_supabase_wins(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "supabase_url", "https://x.supabase.co")
    monkeypatch.setattr(settings, "supabase_anon_key", "k")
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    assert settings.auth_mode == "supabase"


def test_auth_mode_local(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "supabase_url", "")
    monkeypatch.setattr(settings, "supabase_anon_key", "")
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    assert settings.auth_mode == "local"


# --------------------------------------------------------------------------- #
# endpoints
# --------------------------------------------------------------------------- #

async def test_status_shows_local_mode(client: AsyncClient):
    r = await client.get("/api/v1/auth/status")
    assert r.status_code == 200
    body = r.json()
    assert body["authMode"] == "local"
    assert body["localAuthEnabled"] is True
    assert body["bootstrapRequired"] is True
    assert body["setupTokenConfigured"] is True
    assert body["rpid"] == "test.local"


async def test_bootstrap_creates_admin(client: AsyncClient):
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "s3cret-setup-token"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["email"] == "admin@example.com"
    assert body["token"]
    assert "ogi_session" in r.cookies

    # second bootstrap is rejected (already bootstrapped)
    r2 = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "s3cret-setup-token"},
    )
    assert r2.status_code == 409


async def test_bootstrap_rejects_wrong_token(client: AsyncClient):
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "wrong"},
    )
    assert r.status_code == 401


async def test_bootstrap_rejects_non_admin_email(client: AsyncClient):
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "attacker@example.com", "setupToken": "s3cret-setup-token"},
    )
    assert r.status_code == 403


async def test_me_requires_session(client: AsyncClient):
    r = await client.get("/api/v1/auth/me")
    assert r.status_code == 401


async def test_invite_lifecycle(client: AsyncClient):
    # bootstrap to get an admin session
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "s3cret-setup-token"},
    )
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # create invite
    r = await client.post(
        "/api/v1/auth/invites", json={"email": "new@example.com"}, headers=headers
    )
    assert r.status_code == 201
    invite_token = r.json()["token"]

    # peek invite
    r = await client.get(f"/api/v1/auth/invites/{invite_token}")
    assert r.status_code == 200
    assert r.json()["email"] == "new@example.com"

    # list invites
    r = await client.get("/api/v1/auth/invites", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) == 1

    # register/begin with invite token works
    r = await client.post(
        "/api/v1/auth/webauthn/register/begin", json={"inviteToken": invite_token}
    )
    assert r.status_code == 200
    assert "challengeId" in r.json()
    assert "options" in r.json()

    # revoke
    r = await client.delete(f"/api/v1/auth/invites/{invite_token}", headers=headers)
    assert r.status_code == 204


async def test_invites_require_admin(client: AsyncClient):
    r = await client.post("/api/v1/auth/invites", json={"email": "x@example.com"})
    assert r.status_code == 401  # no session -> get_current_user raises 401


async def test_login_begin_returns_options(client: AsyncClient):
    r = await client.post("/api/v1/auth/webauthn/login/begin")
    assert r.status_code == 200
    body = r.json()
    assert "challengeId" in body
    assert "options" in body


async def test_password_fallback_flow(monkeypatch: pytest.MonkeyPatch, client: AsyncClient):
    monkeypatch.setattr(settings, "password_auth_enabled", True)

    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "s3cret-setup-token"},
    )
    token = r.json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    r = await client.post(
        "/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers
    )
    assert r.status_code == 200

    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse"},
    )
    assert r.status_code == 200
    assert r.json()["user"]["email"] == "admin@example.com"

    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "wrong"},
    )
    assert r.status_code == 401


async def test_password_login_disabled_by_default(client: AsyncClient):
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "x"},
    )
    assert r.status_code == 503


async def test_webauthn_complete_rejects_bad_challenge(client: AsyncClient):
    r = await client.post(
        "/api/v1/auth/webauthn/login/complete",
        json={"challengeId": "nope", "assertion": {}},
    )
    assert r.status_code == 400


async def test_register_begin_requires_auth_or_invite(client: AsyncClient):
    r = await client.post("/api/v1/auth/webauthn/register/begin", json={})
    assert r.status_code == 401
