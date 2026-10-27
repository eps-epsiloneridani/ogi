"""Tests for the password+TOTP fallback and its recovery codes + rate limiter.

Covers the RFC 4226/6238 math (pinned against the spec's test vectors), the
base32/provisioning-URI helpers, the full enrollment → login flow over the API,
recovery-code single-use, the TOTP-required gate, and the DB-backed progressive
lockout.
"""
from __future__ import annotations

import hashlib
import os
from uuid import UUID

import pytest
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("OGI_DB_PATH", ":memory:")
os.environ.setdefault("OGI_USE_SQLITE", "true")
os.environ.setdefault("OGI_SUPABASE_URL", "")
os.environ.setdefault("OGI_SUPABASE_ANON_KEY", "")
os.environ.setdefault("OGI_API_KEY_ENCRYPTION_KEY", "k0f97udxEhQ4duzTQESsQNmjUG74U7SMiFd7LrD0WBE=")
os.environ.setdefault("OGI_TELEMETRY_ENABLED", "false")

from ogi.main import app  # noqa: E402
from ogi.config import settings  # noqa: E402
from ogi import totp as totp_util  # noqa: E402
from ogi.api.local_auth import _backoff_seconds  # noqa: E402


@pytest.fixture
def totp_auth(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    monkeypatch.setattr(settings, "webauthn_rpid", "test.local")
    monkeypatch.setattr(settings, "public_origin", "http://test")
    monkeypatch.setattr(settings, "extra_allowed_origins", "")
    monkeypatch.setattr(settings, "setup_token", "s3cret-setup-token")
    monkeypatch.setattr(settings, "admin_emails", "admin@example.com")
    monkeypatch.setattr(settings, "session_secret", "test-session-secret")
    monkeypatch.setattr(settings, "password_auth_enabled", True)
    monkeypatch.setattr(settings, "totp_required", True)
    monkeypatch.setattr(settings, "login_max_attempts", 5)
    monkeypatch.setattr(settings, "login_backoff_base_seconds", 30)
    monkeypatch.setattr(settings, "login_backoff_cap_seconds", 900)
    monkeypatch.setattr(settings, "totp_recovery_code_count", 10)
    yield settings


@pytest.fixture
async def client(totp_auth):
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        async with app.router.lifespan_context(app):
            yield c


# --------------------------------------------------------------------------- #
# RFC 4226 / RFC 6238 math
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("counter,expected", totp_util.RFC4226_VECTORS)
def test_hotp_rfc4226_vectors(counter, expected):
    assert totp_util.hotp(totp_util.RFC4226_SECRET_BYTES, counter, digits=6) == expected


@pytest.mark.parametrize("at,expected", totp_util.RFC6238_VECTORS)
def test_totp_rfc6238_vectors(at, expected):
    secret = totp_util.base32_encode(totp_util.RFC4226_SECRET_BYTES)
    assert totp_util.totp_at(secret, at, digits=8) == expected


def test_base32_roundtrip_and_tolerance():
    secret = totp_util.generate_secret()
    assert len(secret) == 32
    assert totp_util.base32_decode(secret) == totp_util.base32_decode(secret.lower())
    assert totp_util.base32_decode(secret + "====") == totp_util.base32_decode(secret)


def test_verify_totp_window():
    secret = totp_util.generate_secret()
    now = 1_700_000_000
    code = totp_util.totp_now(secret, at=now)
    assert totp_util.verify_totp(secret, code, at=now)
    # ±1 step skew is tolerated (90 s tolerance)
    assert totp_util.verify_totp(secret, code, at=now + 30)
    assert totp_util.verify_totp(secret, code, at=now - 30)
    # outside the window → rejected
    assert not totp_util.verify_totp(secret, code, at=now + 60)


def test_provisioning_uri_shape():
    uri = totp_util.provisioning_uri("admin@example.com", totp_util.generate_secret())
    assert uri.startswith("otpauth://totp/")
    assert "OpenGraph%20Intel:admin@example.com" in uri
    assert "&issuer=OpenGraph%20Intel" in uri
    assert "&algorithm=SHA1&digits=6&period=30" in uri


# --------------------------------------------------------------------------- #
# recovery-code helpers
# --------------------------------------------------------------------------- #

def test_recovery_codes_unique_and_normalizable():
    codes = totp_util.generate_recovery_codes(10)
    assert len(codes) == 10
    assert len(set(codes)) == 10
    for code in codes:
        assert totp_util.normalize_recovery_code(code.lower().replace("-", " ")) == code.replace("-", "")
    hashes = [totp_util.hash_recovery_code(c) for c in codes]
    assert len(set(hashes)) == 10


def test_recovery_code_format_has_80_bits():
    codes = totp_util.generate_recovery_codes(3)
    for code in codes:
        groups = code.split("-")
        assert len(groups) == 4
        assert all(len(g) == 4 for g in groups)
        # 16 symbols over a 32-symbol alphabet == 80 bits of entropy
        assert len(totp_util.normalize_recovery_code(code)) == 16


def test_recovery_code_hash_is_argon2():
    code = totp_util.generate_recovery_codes(1)[0]
    assert totp_util.hash_recovery_code(code).startswith("$argon2")


def test_recovery_code_verify_accepts_argon2_and_legacy():
    code = totp_util.generate_recovery_codes(1)[0]
    other = totp_util.generate_recovery_codes(1)[0]

    # New argon2 path.
    argon2_hash = totp_util.hash_recovery_code(code)
    assert totp_util.verify_recovery_code(argon2_hash, code)
    assert not totp_util.verify_recovery_code(argon2_hash, other)

    # Legacy unsalted SHA-256 digest path (pre-upgrade codes).
    legacy = hashlib.sha256(totp_util.normalize_recovery_code(code).encode("ascii")).hexdigest()
    assert totp_util.verify_recovery_code(legacy, code)
    assert not totp_util.verify_recovery_code(legacy, other)


# --------------------------------------------------------------------------- #
# progressive backoff math
# --------------------------------------------------------------------------- #

def test_backoff_below_threshold_is_none():
    assert _backoff_seconds(0) is None
    assert _backoff_seconds(4) is None


def test_backoff_grows_exponentially_then_caps():
    assert _backoff_seconds(5) == 30       # threshold reached → base * 2^0
    assert _backoff_seconds(6) == 60       # base * 2^1
    assert _backoff_seconds(7) == 120      # base * 2^2
    assert _backoff_seconds(20) == 900     # capped


# --------------------------------------------------------------------------- #
# end-to-end enrollment + login + recovery + lockout
# --------------------------------------------------------------------------- #

async def _bootstrap_admin(client: AsyncClient) -> dict:
    r = await client.post(
        "/api/v1/auth/bootstrap",
        json={"email": "admin@example.com", "setupToken": "s3cret-setup-token"},
    )
    assert r.status_code == 200
    token = r.json()["token"]
    return {"Authorization": f"Bearer {token}"}


async def _enroll(client: AsyncClient, headers: dict) -> tuple[str, list[str]]:
    """Set a password, enroll TOTP, return (secret, recovery_codes)."""
    r = await client.post("/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers)
    assert r.status_code == 200

    r = await client.post("/api/v1/auth/totp/enroll/begin", headers=headers)
    assert r.status_code == 200
    body = r.json()
    secret = body["secret"]
    assert body["otpauthUri"].startswith("otpauth://totp/")
    assert body["qrDataUri"].startswith("data:image/svg+xml;base64,")

    code = totp_util.totp_now(secret)
    r = await client.post("/api/v1/auth/totp/enroll/complete", json={"code": code}, headers=headers)
    assert r.status_code == 200
    recovery_codes = r.json()["recoveryCodes"]
    assert len(recovery_codes) == 10
    return secret, recovery_codes


async def test_totp_required_blocks_password_only(client: AsyncClient):
    headers = await _bootstrap_admin(client)
    await client.post("/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers)
    # Password is set but TOTP is not enrolled → blocked when totp_required=true.
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse"},
    )
    assert r.status_code == 403


async def test_full_password_totp_login(client: AsyncClient):
    headers = await _bootstrap_admin(client)
    secret, _ = await _enroll(client, headers)

    # correct password + current TOTP → success
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "totpCode": totp_util.totp_now(secret)},
    )
    assert r.status_code == 200
    assert r.json()["user"]["email"] == "admin@example.com"

    # wrong TOTP → 401
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "totpCode": "000000"},
    )
    assert r.status_code == 401


async def test_recovery_code_is_single_use(client: AsyncClient):
    headers = await _bootstrap_admin(client)
    _, recovery_codes = await _enroll(client, headers)
    code = recovery_codes[0]

    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "recoveryCode": code},
    )
    assert r.status_code == 200

    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "recoveryCode": code},
    )
    assert r.status_code == 401  # already used


async def test_lockout_after_five_bad_otps(client: AsyncClient):
    headers = await _bootstrap_admin(client)
    secret, _ = await _enroll(client, headers)

    for _ in range(5):
        r = await client.post(
            "/api/v1/auth/password/login",
            json={"email": "admin@example.com", "password": "correct-horse", "totpCode": "000000"},
        )
        assert r.status_code == 401

    # Sixth attempt is locked even with a CORRECT code.
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "totpCode": totp_util.totp_now(secret)},
    )
    assert r.status_code == 429
    assert "Retry-After" in r.headers


async def test_totp_remove_requires_password(client: AsyncClient):
    headers = await _bootstrap_admin(client)
    await _enroll(client, headers)

    r = await client.post("/api/v1/auth/totp/remove", json={}, headers=headers)
    assert r.status_code == 401  # no password → rejected

    r = await client.post("/api/v1/auth/totp/remove", json={"password": "correct-horse"}, headers=headers)
    assert r.status_code == 200

    r = await client.get("/api/v1/auth/totp/status", headers=headers)
    assert r.json()["totpEnrolled"] is False


async def test_totp_status_reflects_state(client: AsyncClient):
    headers = await _bootstrap_admin(client)
    r = await client.get("/api/v1/auth/totp/status", headers=headers)
    assert r.json() == {"totpEnrolled": False, "hasPassword": False, "recoveryCodesRemaining": 0}

    await _enroll(client, headers)
    r = await client.get("/api/v1/auth/totp/status", headers=headers)
    assert r.json()["totpEnrolled"] is True
    assert r.json()["hasPassword"] is True
    assert r.json()["recoveryCodesRemaining"] == 10


async def test_recovery_code_regenerate_replaces_set(client: AsyncClient):
    headers = await _bootstrap_admin(client)
    _, first = await _enroll(client, headers)

    r = await client.post(
        "/api/v1/auth/recovery-codes/regenerate", json={"password": "correct-horse"}, headers=headers
    )
    assert r.status_code == 200
    second = r.json()["recoveryCodes"]
    assert set(first) != set(second)

    # old codes are gone: login with an old code fails
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "recoveryCode": first[0]},
    )
    assert r.status_code == 401


# --------------------------------------------------------------------------- #
# TOTP secret encryption at rest (A-SEC-04)
# --------------------------------------------------------------------------- #

async def _admin_user_id(client: AsyncClient, headers: dict) -> UUID:
    me = await client.get("/api/v1/auth/me", headers=headers)
    return UUID(me.json()["id"])


async def test_totp_secret_is_encrypted_at_rest(client: AsyncClient):
    from ogi.db import database as db
    from ogi.models import LocalAuthUser

    headers = await _bootstrap_admin(client)
    await client.post("/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers)

    r = await client.post("/api/v1/auth/totp/enroll/begin", headers=headers)
    assert r.status_code == 200
    plaintext = r.json()["secret"]

    user_id = await _admin_user_id(client, headers)
    maker = db.async_session_maker
    assert maker is not None
    async with maker() as s:
        row = await s.get(LocalAuthUser, user_id)
        assert row is not None
        assert row.totp_secret.startswith("v1:")
        assert plaintext not in row.totp_secret

    # decrypt-on-verify still works: enrollment completes against the ciphertext
    code = totp_util.totp_now(plaintext)
    r = await client.post("/api/v1/auth/totp/enroll/complete", json={"code": code}, headers=headers)
    assert r.status_code == 200


async def test_legacy_plaintext_totp_secret_is_tolerated_and_reencrypted(client: AsyncClient):
    from datetime import datetime, timezone

    from ogi.db import database as db
    from ogi.models import LocalAuthUser

    headers = await _bootstrap_admin(client)
    await client.post("/api/v1/auth/password/set", json={"password": "correct-horse"}, headers=headers)
    user_id = await _admin_user_id(client, headers)

    secret = totp_util.generate_secret()
    # Simulate a pre-upgrade row: plaintext base32 secret, already enrolled.
    maker = db.async_session_maker
    assert maker is not None
    async with maker() as s:
        row = await s.get(LocalAuthUser, user_id)
        assert row is not None
        row.totp_secret = secret
        row.totp_enrolled_at = datetime.now(timezone.utc)
        await s.commit()

    # Password + TOTP login succeeds against the legacy plaintext secret.
    r = await client.post(
        "/api/v1/auth/password/login",
        json={"email": "admin@example.com", "password": "correct-horse", "totpCode": totp_util.totp_now(secret)},
    )
    assert r.status_code == 200

    # And the plaintext secret is re-encrypted at rest on successful use.
    async with maker() as s:
        row = await s.get(LocalAuthUser, user_id)
        assert row is not None
        assert row.totp_secret.startswith("v1:")
        assert secret not in row.totp_secret


# --------------------------------------------------------------------------- #
# recovery-code atomic single-use (A-SEC-08)
# --------------------------------------------------------------------------- #

async def test_recovery_code_consume_is_atomic_single_use(client: AsyncClient):
    from ogi.api.local_auth import _consume_recovery_code
    from ogi.db import database as db
    from ogi.models import TotpRecoveryCode

    headers = await _bootstrap_admin(client)
    user_id = await _admin_user_id(client, headers)
    code = totp_util.generate_recovery_codes(1)[0]

    maker = db.async_session_maker
    assert maker is not None
    async with maker() as s:
        s.add(TotpRecoveryCode(code_hash=totp_util.hash_recovery_code(code), user_id=user_id))
        await s.commit()

    # First redeem wins; a second redeem of the same code is refused via the
    # conditional-update rowcount (closes the concurrent-replay race).
    async with maker() as s:
        assert await _consume_recovery_code(s, user_id, code) is True
    async with maker() as s:
        assert await _consume_recovery_code(s, user_id, code) is False
