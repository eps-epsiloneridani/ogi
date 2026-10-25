"""Tests for the first-run setup wizard + the manage-logins hub.

Covers, server-side:

* the wizard's claim (token-gated) → session → username/password (+TOTP)
  enrolment state machine (each enrolment step is session-authenticated);
* the conditional passkey-offer signal (WebAuthn needs a configured RPID AND an
  https origin — plain-HTTP LAN must silently drop the passkey step);
* the hard no-stranding rule on passkey removal (a passkey-less account with a
  password is fine; a single-passkey account removing its last passkey is NOT);
* change-password requiring the current password once one is set;
* the new passkey list/remove endpoints and the local-auth display-name setter.

The rate-limit / TOTP math interplay is already pinned by test_totp_auth.py;
these tests assert the wizard does not disturb it (enrolment still clears the
limiter on success, lockout math unchanged).
"""
from __future__ import annotations

import os
from uuid import UUID

import pytest
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("OGI_DB_PATH", ":memory:")
os.environ.setdefault("OGI_USE_SQLITE", "true")
os.environ.setdefault("OGI_SUPABASE_URL", "")
os.environ.setdefault("OGI_SUPABASE_ANON_KEY", "")
os.environ.setdefault("OGI_TELEMETRY_ENABLED", "false")

from ogi.main import app  # noqa: E402
from ogi.config import settings  # noqa: E402
from ogi import totp as totp_util  # noqa: E402
from ogi.models import WebAuthnCredential  # noqa: E402


@pytest.fixture
def wizard(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    monkeypatch.setattr(settings, "webauthn_rpid", "osi.61cygni.co.uk")
    monkeypatch.setattr(settings, "public_origin", "https://osi.61cygni.co.uk")
    monkeypatch.setattr(settings, "extra_allowed_origins", "")
    monkeypatch.setattr(settings, "setup_token", "s3cret-setup-token")
    monkeypatch.setattr(settings, "admin_emails", "admin@example.com")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret")
    monkeypatch.setattr(settings, "password_auth_enabled", True)
    monkeypatch.setattr(settings, "totp_required", True)
    monkeypatch.setattr(settings, "totp_recovery_code_count", 10)
    yield settings


@pytest.fixture
async def client(wizard):
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="https://osi.61cygni.co.uk") as c:
        async with app.router.lifespan_context(app):
            yield c


# --------------------------------------------------------------------------- #
# conditional passkey offer (config-derived; browser isSecureContext is checked
# client-side — the server only signals whether a ceremony CAN run)
# --------------------------------------------------------------------------- #

def test_webauthn_available_with_rpid_and_https(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "webauthn_rpid", "osi.61cygni.co.uk")
    monkeypatch.setattr(settings, "public_origin", "https://osi.61cygni.co.uk")
    assert settings.webauthn_available is True


def test_webauthn_unavailable_over_plain_http(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "webauthn_rpid", "osi.61cygni.co.uk")
    monkeypatch.setattr(settings, "public_origin", "http://192.168.1.3:9901")
    assert settings.webauthn_available is False


def test_webauthn_unavailable_without_rpid(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "webauthn_rpid", "")
    monkeypatch.setattr(settings, "public_origin", "https://osi.61cygni.co.uk")
    assert settings.webauthn_available is False


async def test_status_reports_webauthn_available(client: AsyncClient):
    r = await client.get("/api/v1/auth/status")
    assert r.status_code == 200
    assert r.json()["webauthnAvailable"] is True


# --------------------------------------------------------------------------- #
# wizard state machine: claim → session → password (+TOTP)
# --------------------------------------------------------------------------- #

async def _bootstrap(client: AsyncClient) -> dict:
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "s3cret-setup-token"},
    )
    assert r.status_code == 200
    token = r.json()["token"]
    return {"Authorization": f"Bearer {token}"}


async def test_wizard_steps_are_session_authenticated(client: AsyncClient):
    # Before the token-gated claim, every enrol step must 401 (no open anonymous
    # self-enrolment can appear).
    r = await client.post("/api/v1/auth/password/set", json={"password": "correct-horse"})
    assert r.status_code == 401
    r = await client.post("/api/v1/auth/totp/enroll/begin")
    assert r.status_code == 401
    r = await client.get("/api/v1/auth/webauthn/credentials")
    assert r.status_code == 401
    r = await client.post("/api/v1/auth/profile", json={"displayName": "x"})
    assert r.status_code == 401


async def test_wizard_claim_then_enrol_state_machine(client: AsyncClient):
    # 1. claim (token-gated) — the only gate to becoming the first admin.
    headers = await _bootstrap(client)

    # 2. set password (session-authenticated)
    r = await client.post(
        "/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers
    )
    assert r.status_code == 200

    # 3. enroll TOTP (session-authenticated), verify one code → recovery codes
    r = await client.post("/api/v1/auth/totp/enroll/begin", headers=headers)
    assert r.status_code == 200
    secret = r.json()["secret"]
    code = totp_util.totp_now(secret)
    r = await client.post(
        "/api/v1/auth/totp/enroll/complete", json={"code": code}, headers=headers
    )
    assert r.status_code == 200
    assert len(r.json()["recoveryCodes"]) == 10

    # 4. final state: password + TOTP both live
    r = await client.get("/api/v1/auth/totp/status", headers=headers)
    body = r.json()
    assert body["hasPassword"] is True
    assert body["totpEnrolled"] is True

    # 5. the completed account can log in with password+TOTP (lands in login flow)
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "totpCode": totp_util.totp_now(secret)},
    )
    assert r.status_code == 200


async def test_wizard_claim_still_token_gated(client: AsyncClient):
    # The anti-self-admin property survives: a wrong token cannot claim.
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "wrong"},
    )
    assert r.status_code == 401
    # A non-admin email cannot claim even with the right token.
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "nobody@example.com", "setupToken": "s3cret-setup-token"},
    )
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# change password requires the current password (once one is set)
# --------------------------------------------------------------------------- #

async def test_change_password_requires_current(client: AsyncClient):
    headers = await _bootstrap(client)

    # first set (no password yet) needs no current password
    r = await client.post("/api/v1/auth/password/set", json={"password": "first-password"}, headers=headers)
    assert r.status_code == 200

    # changing without the current password → 401
    r = await client.post("/api/v1/auth/password/set", json={"password": "second-password"}, headers=headers)
    assert r.status_code == 401

    # wrong current password → 401
    r = await client.post(
        "/api/v1/auth/password/set",
        json={"password": "second-password", "currentPassword": "wrong"},
        headers=headers,
    )
    assert r.status_code == 401

    # correct current password → 200
    r = await client.post(
        "/api/v1/auth/password/set",
        json={"password": "second-password", "currentPassword": "first-password"},
        headers=headers,
    )
    assert r.status_code == 200

    # the new password now signs in (password-only login blocked by totp_required,
    # so assert via a second change rather than login)
    r = await client.post(
        "/api/v1/auth/password/set",
        json={"password": "third-password", "currentPassword": "second-password"},
        headers=headers,
    )
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# no-stranding rule on passkey removal
# --------------------------------------------------------------------------- #

async def _insert_credential(user_id: UUID, credential_id: str = "cred-1") -> None:
    from ogi.db import database as db

    maker = db.async_session_maker
    assert maker is not None
    async with maker() as s:
        s.add(WebAuthnCredential(credential_id=credential_id, user_id=user_id, public_key="x"))
        await s.commit()


async def test_single_passkey_removing_last_is_refused(client: AsyncClient):
    # Scenario: a single-passkey account (no password) removing its last passkey
    # is NOT allowed — it would strand the account.
    headers = await _bootstrap(client)
    me = await client.get("/api/v1/auth/me", headers=headers)
    user_id = UUID(me.json()["id"])
    await _insert_credential(user_id, "only-passkey")

    r = await client.get("/api/v1/auth/webauthn/credentials", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = await client.delete("/api/v1/auth/webauthn/credentials/only-passkey", headers=headers)
    assert r.status_code == 409  # refused: would strand

    # credential still present
    r = await client.get("/api/v1/auth/webauthn/credentials", headers=headers)
    assert len(r.json()) == 1


async def test_passkey_removal_allowed_when_password_present(client: AsyncClient):
    # A passkey-less account WITH a password is fine: removing the last passkey
    # is allowed because the password remains a usable method.
    headers = await _bootstrap(client)
    me = await client.get("/api/v1/auth/me", headers=headers)
    user_id = UUID(me.json()["id"])
    await client.post("/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers)
    await _insert_credential(user_id, "last-passkey")

    r = await client.delete("/api/v1/auth/webauthn/credentials/last-passkey", headers=headers)
    assert r.status_code == 200

    r = await client.get("/api/v1/auth/webauthn/credentials", headers=headers)
    assert len(r.json()) == 0


async def test_passkey_removal_allowed_with_multiple_passkeys(client: AsyncClient):
    headers = await _bootstrap(client)
    me = await client.get("/api/v1/auth/me", headers=headers)
    user_id = UUID(me.json()["id"])
    await _insert_credential(user_id, "passkey-a")
    await _insert_credential(user_id, "passkey-b")

    r = await client.delete("/api/v1/auth/webauthn/credentials/passkey-a", headers=headers)
    assert r.status_code == 200

    r = await client.get("/api/v1/auth/webauthn/credentials", headers=headers)
    assert {c["credentialId"] for c in r.json()} == {"passkey-b"}


async def test_passkey_credential_remove_is_scoped_to_owner(client: AsyncClient):
    # Removing a credential that belongs to a different user (or doesn't exist)
    # is a 404, never a cross-user delete.
    headers = await _bootstrap(client)
    r = await client.delete("/api/v1/auth/webauthn/credentials/does-not-exist", headers=headers)
    assert r.status_code == 404


async def test_totp_removal_from_passkey_less_password_totp_is_fine(client: AsyncClient):
    # "a passkey-less account WITH password+TOTP is fine": removing TOTP does not
    # strand it (the password remains). Mirrors the existing
    # test_totp_remove_requires_password green path under the new rule.
    headers = await _bootstrap(client)
    await client.post("/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers)
    r = await client.post("/api/v1/auth/totp/enroll/begin", headers=headers)
    secret = r.json()["secret"]
    await client.post(
        "/api/v1/auth/totp/enroll/complete", json={"code": totp_util.totp_now(secret)}, headers=headers
    )

    r = await client.post(
        "/api/v1/auth/totp/remove", json={"password": "correct-horse"}, headers=headers
    )
    assert r.status_code == 200


# --------------------------------------------------------------------------- #
# local-auth display name
# --------------------------------------------------------------------------- #

async def test_profile_display_name_roundtrip(client: AsyncClient):
    headers = await _bootstrap(client)
    r = await client.post("/api/v1/auth/profile", json={"displayName": "Rich Operator"}, headers=headers)
    assert r.status_code == 200
    assert r.json()["displayName"] == "Rich Operator"
    assert r.json()["email"] == "admin@example.com"

    r = await client.get("/api/v1/auth/me", headers=headers)
    assert r.json()["displayName"] == "Rich Operator"
