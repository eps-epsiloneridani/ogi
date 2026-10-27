"""Local (passkey-first) auth endpoints.

Activated only when ``settings.auth_mode == "local"`` (Supabase unset +
``OGI_LOCAL_AUTH_ENABLED=true``). Every endpoint here returns 503 when local
auth is not the active mode, so it can never silently weaken the Supabase or
anonymous paths.

Flows:
  * first-run bootstrap: claim an admin email against ``OGI_SETUP_TOKEN``.
  * passkey registration: either authenticated (self adds a credential) or via
    an admin-minted one-time invite (creates the account).
  * passkey login (the primary path), with an optional argon2 password fallback.
  * admin invite mint / list / revoke.
Sessions are stateless HMAC tokens (see ``ogi.auth_tokens``) delivered as an
HttpOnly cookie and accepted identically as ``Authorization: Bearer``.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from cryptography.fernet import Fernet, InvalidToken

from ogi.api.auth import get_current_user, require_admin_user
from ogi.auth_tokens import (
    SESSION_COOKIE_NAME,
    issue_session_token,
    verify_session_token,
)
from ogi.config import settings
from ogi.db.database import get_session
from ogi.models import (
    AuthInvite,
    AuthRateLimit,
    LocalAuthUser,
    TotpRecoveryCode,
    UserProfile,
    WebAuthnChallenge,
    WebAuthnCredential,
)
from ogi import totp as totp_util

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

try:  # argon2 is optional (password fallback is OFF by default)
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHashError

    _ph = PasswordHasher()
    _ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover - only if the optional dep is missing
    _ph = None  # type: ignore[assignment]
    _ARGON2_AVAILABLE = False


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _require_local_auth() -> None:
    if settings.auth_mode != "local":
        raise HTTPException(status_code=503, detail="Local auth is not enabled")


def _as_utc_naive(dt: datetime | None) -> datetime | None:
    """Normalize a datetime to naive UTC (SQLite returns naive datetimes while
    Postgres returns aware ones; comparing the two raises TypeError)."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _now_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


# --------------------------------------------------------------------------- #
# TOTP secret encryption at rest (A-SEC-04)
# --------------------------------------------------------------------------- #

_fernet: Fernet | None = None


def _get_fernet() -> Fernet:
    """The Fernet instance for TOTP-secret encryption, keyed by the same
    OGI_API_KEY_ENCRYPTION_KEY the API-key store already uses."""
    global _fernet
    if _fernet is not None:
        return _fernet
    if not settings.api_key_encryption_key:
        raise HTTPException(
            status_code=500,
            detail="OGI_API_KEY_ENCRYPTION_KEY is required to encrypt TOTP secrets at rest",
        )
    _fernet = Fernet(settings.api_key_encryption_key.encode())
    return _fernet


def _encrypt_totp_secret(plain: str) -> str:
    return "v1:" + _get_fernet().encrypt(plain.encode()).decode()


def _decrypt_totp_secret(stored: str | None) -> str | None:
    """Decrypt a stored TOTP secret. Legacy rows (pre-encryption) hold plaintext
    base32 and are returned verbatim so the caller can re-encrypt on use; an
    undecryptable ``v1:`` token is treated as absent (fail closed)."""
    if not stored:
        return None
    if stored.startswith("v1:"):
        try:
            return _get_fernet().decrypt(stored[3:].encode()).decode()
        except InvalidToken:
            return None
    return stored  # legacy plaintext base32 secret


def _reencrypt_totp_secret_if_legacy(local_user: LocalAuthUser) -> bool:
    """Re-encrypt a legacy plaintext TOTP secret in place (no-op for ``v1:``).

    Returns True when a plaintext secret was re-encrypted, so the caller can
    commit the mutation.
    """
    stored = local_user.totp_secret
    if stored and not stored.startswith("v1:"):
        local_user.totp_secret = _encrypt_totp_secret(stored)
        return True
    return False


def _webauthn_config() -> tuple[str, list[str]]:
    rpid = settings.webauthn_rpid.strip()
    origins = settings.get_expected_origins()
    if not rpid and origins:
        # derive RPID from the primary origin's host
        rpid = origins[0].split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    if not rpid:
        raise HTTPException(
            status_code=503,
            detail="WebAuthn not configured: set OGI_WEBAUTHN_RPID and OGI_PUBLIC_ORIGIN",
        )
    if not origins:
        raise HTTPException(
            status_code=503,
            detail="WebAuthn not configured: OGI_PUBLIC_ORIGIN is empty",
        )
    return rpid, origins


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.session_secure,
        samesite="lax",
        path="/",
    )


async def _extract_local_user_id(request: Request) -> UUID | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth.removeprefix("Bearer ").strip()
    if not token:
        return None
    return verify_session_token(token)


async def _current_local_profile(request: Request, session: AsyncSession) -> UserProfile | None:
    uid = await _extract_local_user_id(request)
    if uid is None:
        return None
    return await session.get(UserProfile, uid)


async def _get_or_create_profile(email: str, session: AsyncSession) -> UserProfile:
    stmt = select(UserProfile).where(UserProfile.email == email.lower().strip())
    result = await session.execute(stmt)
    profile = result.scalar_one_or_none()
    if profile is None:
        profile = UserProfile(id=UUID(int=secrets.randbits(128)), email=email.lower().strip())
        session.add(profile)
        await session.commit()
        await session.refresh(profile)
    return profile


async def _find_profile_by_email(email: str, session: AsyncSession) -> UserProfile | None:
    """Look up a profile by email WITHOUT creating it (login must never mint a
    profile for an unknown address — that would be user enumeration plus junk)."""
    stmt = select(UserProfile).where(UserProfile.email == email.lower().strip())
    result = await session.execute(stmt)
    return result.scalar_one_or_none()


async def _has_any_local_user(session: AsyncSession) -> bool:
    result = await session.execute(select(LocalAuthUser.user_id).limit(1))
    return result.scalar_one_or_none() is not None


async def _count_passkeys(session: AsyncSession, user_id: UUID) -> int:
    stmt = select(WebAuthnCredential).where(WebAuthnCredential.user_id == user_id)
    result = await session.execute(stmt)
    return len(result.scalars().all())


async def _would_strand_on_passkey_removal(session: AsyncSession, user_id: UUID) -> bool:
    """True if removing one more passkey would leave the account with no login
    method at all.

    A login method is a passkey OR a set password. TOTP is a second factor, not
    a method on its own, so a passkey-less account with password(+TOTP) is fine
    and never strands on passkey removal; a single-passkey account with no
    password removing its last passkey is NOT.
    """
    local_user = await session.get(LocalAuthUser, user_id)
    if local_user is not None and local_user.password_hash:
        return False  # password remains → still a usable method
    return await _count_passkeys(session, user_id) <= 1


async def _store_challenge(
    session: AsyncSession, challenge: bytes, kind: str, user_id: UUID | None
) -> str:
    challenge_id = secrets.token_urlsafe(32)
    from webauthn.helpers import bytes_to_base64url

    row = WebAuthnChallenge(
        id=challenge_id,
        challenge=bytes_to_base64url(challenge),
        kind=kind,
        user_id=user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )
    session.add(row)
    await session.commit()
    return challenge_id


async def _consume_challenge(
    session: AsyncSession, challenge_id: str, kind: str
) -> WebAuthnChallenge:
    row = await session.get(WebAuthnChallenge, challenge_id)
    if row is None or row.kind != kind:
        raise HTTPException(status_code=400, detail="Unknown or invalid challenge")
    if _as_utc_naive(row.expires_at) < _now_naive():
        raise HTTPException(status_code=400, detail="Challenge expired")
    await session.delete(row)
    await session.commit()
    return row


# --------------------------------------------------------------------------- #
# TOTP / rate-limit / recovery-code helpers
# --------------------------------------------------------------------------- #

def _backoff_seconds(failed_count: int) -> int | None:
    """Progressive lockout duration for a given failure count.

    The first ``login_max_attempts - 1`` failures carry no lockout (each returns
    a plain 401). Reaching the threshold (the 5th failure by default) engages a
    lock of ``base * 2**(n - max)`` seconds, capped at ``login_backoff_cap_seconds``
    — so "lockout after N bad attempts" means attempt N+1 is rejected.
    """
    if failed_count < settings.login_max_attempts:
        return None
    exp = failed_count - settings.login_max_attempts
    return min(settings.login_backoff_base_seconds * (2 ** exp), settings.login_backoff_cap_seconds)


async def _check_login_rate_limit(session: AsyncSession, email: str) -> None:
    row = await session.get(AuthRateLimit, email.lower().strip())
    if row is not None and row.locked_until is not None:
        locked = _as_utc_naive(row.locked_until)
        if locked > _now_naive():
            retry_after = max(1, int((locked - _now_naive()).total_seconds()))
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )


async def _record_login_failure(session: AsyncSession, email: str) -> None:
    key = email.lower().strip()
    row = await session.get(AuthRateLimit, key)
    if row is None:
        row = AuthRateLimit(key=key, failed_count=0)
        session.add(row)
    row.failed_count += 1
    row.updated_at = _now_naive()
    backoff = _backoff_seconds(row.failed_count)
    if backoff is not None:
        row.locked_until = _now_naive() + timedelta(seconds=backoff)
    await session.commit()


async def _clear_login_failures(session: AsyncSession, email: str) -> None:
    row = await session.get(AuthRateLimit, email.lower().strip())
    if row is not None:
        await session.delete(row)
        await session.commit()


async def _consume_recovery_code(
    session: AsyncSession, user_id: UUID, code: str
) -> bool:
    """Redeem a one-time recovery code; returns False if unknown/used/wrong user."""
    if not code:
        return False
    normalized = totp_util.normalize_recovery_code(code)
    # Legacy fast path: pre-upgrade codes were stored as unsalted SHA-256 hex.
    legacy_hash = hashlib.sha256(normalized.encode("ascii")).hexdigest()
    row = await session.get(TotpRecoveryCode, legacy_hash)
    if row is not None:
        if row.user_id != user_id or row.used_at is not None:
            return False
        row.used_at = _now_naive()
        session.add(row)
        await session.commit()
        return True
    # Argon2 path: iterate the user's unused codes and verify each in place.
    stmt = select(TotpRecoveryCode).where(
        TotpRecoveryCode.user_id == user_id, TotpRecoveryCode.used_at.is_(None)
    )
    result = await session.execute(stmt)
    for row in result.scalars().all():
        if totp_util.verify_recovery_code(row.code_hash, code):
            row.used_at = _now_naive()
            session.add(row)
            await session.commit()
            return True
    return False


async def _unused_recovery_code_count(session: AsyncSession, user_id: UUID) -> int:
    stmt = select(TotpRecoveryCode).where(
        TotpRecoveryCode.user_id == user_id, TotpRecoveryCode.used_at.is_(None)
    )
    result = await session.execute(stmt)
    return len(result.scalars().all())


async def _delete_recovery_codes(session: AsyncSession, user_id: UUID) -> None:
    stmt = select(TotpRecoveryCode).where(TotpRecoveryCode.user_id == user_id)
    result = await session.execute(stmt)
    for row in result.scalars().all():
        await session.delete(row)


def _issue_recovery_codes(session: AsyncSession, user_id: UUID) -> list[str]:
    """Generate fresh recovery codes, store their hashes, return the plaintext."""
    codes = totp_util.generate_recovery_codes(settings.totp_recovery_code_count)
    for code in codes:
        session.add(TotpRecoveryCode(code_hash=totp_util.hash_recovery_code(code), user_id=user_id))
    return codes


def _make_qr_svg_data_uri(text: str) -> str:
    """Render ``text`` as an SVG QR code and return it as a ``data:`` URI.

    Uses the pure-Python ``qrcode`` library (SVG output, no Pillow) so the
    frontend can display the provisioning URI with a plain ``<img>`` and no
    QR logic of its own.
    """
    import base64
    import io

    import qrcode
    from qrcode.image.svg import SvgPathImage

    img = qrcode.make(text, image_factory=SvgPathImage, box_size=10, border=2)
    if hasattr(img, "to_string"):
        raw = img.to_string()
    else:  # pragma: no cover - defensive fallback across qrcode versions
        buf = io.BytesIO()
        img.save(buf)
        raw = buf.getvalue()
    if not isinstance(raw, bytes):
        raw = raw.encode("utf-8")
    return "data:image/svg+xml;base64," + base64.b64encode(raw).decode("ascii")


# --------------------------------------------------------------------------- #
# public config / bootstrap / status
# --------------------------------------------------------------------------- #

@router.get("/status")
async def auth_status(session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    """Public: describes the active auth mode so the SPA can render the right UI."""
    if settings.auth_mode != "local":
        return {"authMode": settings.auth_mode, "localAuthEnabled": False}

    rpid, origins = _webauthn_config()
    return {
        "authMode": "local",
        "localAuthEnabled": True,
        "passwordAuthEnabled": bool(settings.password_auth_enabled and _ARGON2_AVAILABLE),
        "totpRequired": bool(settings.totp_required),
        "rpid": rpid,
        "origins": origins,
        "webauthnAvailable": settings.webauthn_available,
        "bootstrapRequired": not await _has_any_local_user(session),
        "setupTokenConfigured": bool(settings.setup_token),
    }


@router.post("/bootstrap", status_code=200)
async def bootstrap(
    request: Request,
    response: Response,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """First-run: claim an admin email against the operator's OGI_SETUP_TOKEN."""
    _require_local_auth()
    email = (payload.get("email") or "").strip().lower()
    setup_token = payload.get("setupToken") or ""

    if await _has_any_local_user(session):
        raise HTTPException(status_code=409, detail="Already bootstrapped")

    if not settings.setup_token:
        raise HTTPException(status_code=503, detail="Setup token is not configured")
    if not secrets.compare_digest(setup_token, settings.setup_token):
        raise HTTPException(status_code=401, detail="Invalid setup token")
    if not settings.is_admin_email(email):
        raise HTTPException(status_code=403, detail="Email is not an admin email")

    profile = await _get_or_create_profile(email, session)
    existing = await session.get(LocalAuthUser, profile.id)
    if existing is None:
        session.add(LocalAuthUser(user_id=profile.id))
        await session.commit()

    token = issue_session_token(profile.id)
    _set_session_cookie(response, token)
    return {"user": _profile_dict(profile), "token": token}


def _transports_from_attestation(attestation: dict[str, Any]) -> list[str]:
    """Accept transports as plain strings (from @simplewebauthn JSON) or as
    py_webauthn enums with a .value — both occurred in the field; a 500 on the
    happy path in the first-run ceremony is not an acceptable failure mode."""
    data = attestation or {}
    return [
        t if isinstance(t, str) else getattr(t, "value", str(t))
        for t in (data.get("response", {}).get("transports") or [])
    ]


# --------------------------------------------------------------------------- #
# passkey registration
# --------------------------------------------------------------------------- #

@router.post("/webauthn/register/begin")
async def webauthn_register_begin(
    request: Request,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    rpid, origins = _webauthn_config()

    from webauthn import generate_registration_options, options_to_json
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    user_id: UUID | None = None
    email: str | None = None

    invite_token = (payload.get("inviteToken") or "").strip()
    if invite_token:
        invite = await _valid_invite(invite_token, session)
        email = invite.email
    else:
        profile = await _current_local_profile(request, session)
        if profile is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        user_id = profile.id
        email = profile.email or "user"

    options = generate_registration_options(
        rp_id=rpid,
        rp_name="OpenGraph Intel",
        user_name=email,
        user_id=None if user_id is None else user_id.bytes,
        user_display_name=email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )

    challenge_id = await _store_challenge(
        session, options.challenge, "registration", user_id
    )
    return {
        "challengeId": challenge_id,
        "options": json.loads(options_to_json(options)),
        "inviteToken": invite_token or None,
    }


@router.post("/webauthn/register/complete")
async def webauthn_register_complete(
    request: Request,
    response: Response,
    payload: dict[str, Any],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    rpid, origins = _webauthn_config()

    from webauthn import verify_registration_response
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

    challenge_id = payload.get("challengeId") or ""
    attestation = payload.get("attestation") or {}
    invite_token = (payload.get("inviteToken") or "").strip()

    challenge = await _consume_challenge(session, challenge_id, "registration")

    user_id: UUID
    invite: AuthInvite | None = None
    if invite_token:
        invite = await _valid_invite(invite_token, session)
        profile = await _get_or_create_profile(invite.email, session)
        user_id = profile.id
    elif challenge.user_id is not None:
        user_id = challenge.user_id
    else:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        verified = verify_registration_response(
            credential=attestation,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_rp_id=rpid,
            expected_origin=origins,
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Passkey registration verification failed: %s", exc)
        raise HTTPException(status_code=400, detail="Passkey registration failed")

    credential = WebAuthnCredential(
        credential_id=bytes_to_base64url(verified.credential_id),
        user_id=user_id,
        public_key=bytes_to_base64url(verified.credential_public_key),
        sign_count=verified.sign_count,
        transports=json.dumps(_transports_from_attestation(attestation)),
        aaguid=str(verified.aaguid),
    )
    session.add(credential)
    if invite is not None:
        # Atomic conditional consume: exactly one concurrent caller wins.
        # Zero rows updated means another caller claimed it first — roll back
        # the credential we just staged and fail closed.
        if not await _consume_invite_atomically(session, invite_token):
            await session.rollback()
            raise HTTPException(status_code=410, detail="Invite already used")
    await session.commit()

    profile = await session.get(UserProfile, user_id)
    token = issue_session_token(user_id)
    _set_session_cookie(response, token)
    return {"user": _profile_dict(profile), "token": token}


# --------------------------------------------------------------------------- #
# passkey management (list / remove — the manage-logins hub)
# --------------------------------------------------------------------------- #

def _credential_dict(cred: WebAuthnCredential) -> dict[str, Any]:
    transports: list[str] = []
    try:
        raw = json.loads(cred.transports or "[]")
        if isinstance(raw, list):
            transports = [t if isinstance(t, str) else str(t) for t in raw]
    except (ValueError, TypeError):
        transports = []
    return {
        "credentialId": cred.credential_id,
        "transports": transports,
        "aaguid": cred.aaguid,
        "createdAt": cred.created_at.isoformat() if cred.created_at else None,
        "lastUsedAt": cred.last_used_at.isoformat() if cred.last_used_at else None,
    }


@router.get("/webauthn/credentials")
async def webauthn_credentials_list(
    request: Request, session: AsyncSession = Depends(get_session)
) -> list[dict[str, Any]]:
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    stmt = select(WebAuthnCredential).where(WebAuthnCredential.user_id == profile.id).order_by(
        WebAuthnCredential.created_at.desc()
    )
    result = await session.execute(stmt)
    return [_credential_dict(c) for c in result.scalars().all()]


@router.delete("/webauthn/credentials/{credential_id}", status_code=200)
async def webauthn_credential_remove(
    request: Request,
    credential_id: str,
    session: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    cred = await session.get(WebAuthnCredential, credential_id)
    if cred is None or cred.user_id != profile.id:
        raise HTTPException(status_code=404, detail="Credential not found")

    if await _would_strand_on_passkey_removal(session, profile.id):
        raise HTTPException(
            status_code=409,
            detail="Removing this passkey would leave the account with no way to sign in",
        )

    await session.delete(cred)
    await session.commit()
    return {"ok": True}

@router.post("/webauthn/login/begin")
async def webauthn_login_begin(
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    rpid, _ = _webauthn_config()

    from webauthn import generate_authentication_options, options_to_json
    from webauthn.helpers.structs import UserVerificationRequirement

    options = generate_authentication_options(
        rp_id=rpid, user_verification=UserVerificationRequirement.PREFERRED
    )
    challenge_id = await _store_challenge(
        session, options.challenge, "authentication", None
    )
    return {"challengeId": challenge_id, "options": json.loads(options_to_json(options))}


@router.post("/webauthn/login/complete")
async def webauthn_login_complete(
    request: Request,
    response: Response,
    payload: dict[str, Any],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    rpid, origins = _webauthn_config()

    from webauthn import verify_authentication_response
    from webauthn.helpers import base64url_to_bytes

    challenge_id = payload.get("challengeId") or ""
    assertion = payload.get("assertion") or {}

    challenge = await _consume_challenge(session, challenge_id, "authentication")

    credential_id = (assertion.get("id") or "").strip()
    credential = await session.get(WebAuthnCredential, credential_id)
    if credential is None:
        raise HTTPException(status_code=401, detail="Unknown credential")

    try:
        verified = verify_authentication_response(
            credential=assertion,
            expected_challenge=base64url_to_bytes(challenge.challenge),
            expected_rp_id=rpid,
            expected_origin=origins,
            credential_public_key=base64url_to_bytes(credential.public_key),
            credential_current_sign_count=credential.sign_count,
            require_user_verification=True,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Passkey login verification failed: %s", exc)
        raise HTTPException(status_code=401, detail="Passkey login failed")

    credential.sign_count = verified.new_sign_count
    credential.last_used_at = datetime.now(timezone.utc)
    session.add(credential)
    await session.commit()

    profile = await session.get(UserProfile, credential.user_id)
    if profile is None:
        raise HTTPException(status_code=401, detail="Unknown user")

    token = issue_session_token(profile.id)
    _set_session_cookie(response, token)
    return {"user": _profile_dict(profile), "token": token}


# --------------------------------------------------------------------------- #
# password fallback (env-gated) + TOTP second factor + recovery codes
# --------------------------------------------------------------------------- #

@router.post("/password/login")
async def password_login(
    request: Request,
    response: Response,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    if not (settings.password_auth_enabled and _ARGON2_AVAILABLE):
        raise HTTPException(status_code=503, detail="Password auth is disabled")

    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""
    totp_code = (payload.get("totpCode") or "").strip()
    recovery_code = (payload.get("recoveryCode") or "").strip()

    await _check_login_rate_limit(session, email)

    profile = await _find_profile_by_email(email, session)
    if profile is None:
        await _record_login_failure(session, email)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    local_user = await session.get(LocalAuthUser, profile.id)
    if local_user is None or not local_user.password_hash:
        await _record_login_failure(session, email)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    try:
        _ph.verify(local_user.password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        await _record_login_failure(session, email)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Password is correct. Enforce the second factor when enrolled (or required).
    totp_secret = _decrypt_totp_secret(local_user.totp_secret)
    enrolled = bool(totp_secret and local_user.totp_enrolled_at)
    if enrolled:
        if recovery_code:
            if not await _consume_recovery_code(session, profile.id, recovery_code):
                await _record_login_failure(session, email)
                raise HTTPException(status_code=401, detail="Invalid recovery code")
        elif totp_code:
            if not totp_util.verify_totp(totp_secret, totp_code):
                await _record_login_failure(session, email)
                raise HTTPException(status_code=401, detail="Invalid TOTP code")
            if _reencrypt_totp_secret_if_legacy(local_user):
                session.add(local_user)
                await session.commit()
        else:
            raise HTTPException(status_code=401, detail="TOTP code required")
    elif settings.totp_required:
        # Password-only login is disabled until the user enrolls TOTP.
        raise HTTPException(status_code=403, detail="TOTP enrollment required before password login")

    await _clear_login_failures(session, email)
    token = issue_session_token(profile.id)
    _set_session_cookie(response, token)
    return {"user": _profile_dict(profile), "token": token}


@router.post("/password/set")
async def password_set(
    request: Request,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    _require_local_auth()
    if not (settings.password_auth_enabled and _ARGON2_AVAILABLE):
        raise HTTPException(status_code=503, detail="Password auth is disabled")

    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    password = payload.get("password") or ""
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Password too short")

    local_user = await session.get(LocalAuthUser, profile.id)
    # Change-password (once a password exists) requires the current password, so
    # a stolen session alone cannot silently rotate the credential.
    if local_user is not None and local_user.password_hash:
        current = payload.get("currentPassword") or ""
        try:
            _ph.verify(local_user.password_hash, current)
        except (VerifyMismatchError, InvalidHashError):
            raise HTTPException(
                status_code=401, detail="Current password is required to change the password"
            )
    if local_user is None:
        local_user = LocalAuthUser(user_id=profile.id)
        session.add(local_user)
    local_user.password_hash = _ph.hash(password)
    await session.commit()
    return {"ok": True}


@router.get("/totp/status")
async def totp_status(
    request: Request, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")
    local_user = await session.get(LocalAuthUser, profile.id)
    enrolled = bool(local_user is not None and local_user.totp_enrolled_at)
    return {
        "totpEnrolled": enrolled,
        "hasPassword": bool(local_user is not None and local_user.password_hash),
        "recoveryCodesRemaining": (
            await _unused_recovery_code_count(session, profile.id) if enrolled else 0
        ),
    }


@router.post("/totp/enroll/begin")
async def totp_enroll_begin(
    request: Request, session: AsyncSession = Depends(get_session)
) -> dict[str, str]:
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    local_user = await session.get(LocalAuthUser, profile.id)
    if local_user is None:
        local_user = LocalAuthUser(user_id=profile.id)
        session.add(local_user)
    if local_user.totp_enrolled_at is not None:
        raise HTTPException(status_code=409, detail="TOTP already enrolled")

    secret = totp_util.generate_secret()
    local_user.totp_secret = _encrypt_totp_secret(secret)  # encrypted at rest
    await session.commit()

    uri = totp_util.provisioning_uri(profile.email or "user", secret)
    return {"secret": secret, "otpauthUri": uri, "qrDataUri": _make_qr_svg_data_uri(uri)}


@router.post("/totp/enroll/complete")
async def totp_enroll_complete(
    request: Request,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    local_user = await session.get(LocalAuthUser, profile.id)
    if local_user is None:
        raise HTTPException(status_code=400, detail="No pending enrollment")
    if local_user.totp_enrolled_at is not None:
        raise HTTPException(status_code=409, detail="TOTP already enrolled")

    secret = _decrypt_totp_secret(local_user.totp_secret)
    if not secret:
        raise HTTPException(status_code=400, detail="No pending enrollment")

    code = (payload.get("code") or "").strip()
    if not totp_util.verify_totp(secret, code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    _reencrypt_totp_secret_if_legacy(local_user)
    local_user.totp_enrolled_at = _now_naive()
    recovery_codes = _issue_recovery_codes(session, profile.id)
    await session.commit()
    return {"recoveryCodes": recovery_codes}


@router.post("/totp/remove")
async def totp_remove(
    request: Request,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, bool]:
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    local_user = await session.get(LocalAuthUser, profile.id)
    if local_user is None or not local_user.totp_enrolled_at:
        raise HTTPException(status_code=400, detail="TOTP not enrolled")

    # Fresh confirmation: require the account password when one is set; a
    # passkey-only user (no password) confirms with their existing session.
    if local_user.password_hash:
        password = payload.get("password") or ""
        try:
            _ph.verify(local_user.password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            raise HTTPException(status_code=401, detail="Password required to remove TOTP")

    local_user.totp_secret = None
    local_user.totp_enrolled_at = None
    await _delete_recovery_codes(session, profile.id)
    await session.commit()
    return {"ok": True}


@router.post("/recovery-codes/regenerate")
async def recovery_codes_regenerate(
    request: Request,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    local_user = await session.get(LocalAuthUser, profile.id)
    if local_user is None or not local_user.totp_enrolled_at:
        raise HTTPException(status_code=400, detail="TOTP not enrolled")

    if local_user.password_hash:
        password = payload.get("password") or ""
        try:
            _ph.verify(local_user.password_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            raise HTTPException(status_code=401, detail="Password required")

    await _delete_recovery_codes(session, profile.id)
    recovery_codes = _issue_recovery_codes(session, profile.id)
    await session.commit()
    return {"recoveryCodes": recovery_codes}


# --------------------------------------------------------------------------- #
# session / me / logout
# --------------------------------------------------------------------------- #

@router.get("/me")
async def auth_me(
    request: Request, session: AsyncSession = Depends(get_session)
) -> dict[str, Any]:
    if settings.auth_mode == "supabase":
        user = await get_current_user(request, session)
        return _profile_dict(user)
    if settings.auth_mode == "local":
        profile = await _current_local_profile(request, session)
        if profile is None:
            raise HTTPException(status_code=401, detail="Not authenticated")
        return _profile_dict(profile)
    return _profile_dict(None)


@router.post("/profile")
async def profile_update(
    request: Request,
    payload: dict[str, str],
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    """Set the optional display name for the local-auth user (session-authenticated)."""
    _require_local_auth()
    profile = await _current_local_profile(request, session)
    if profile is None:
        raise HTTPException(status_code=401, detail="Not authenticated")

    display_name = (payload.get("displayName") or "").strip()
    profile.display_name = display_name[:200]  # defensive length cap
    session.add(profile)
    await session.commit()
    await session.refresh(profile)
    return _profile_dict(profile)


@router.post("/logout", status_code=200)
async def logout(response: Response) -> dict[str, bool]:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    return {"ok": True}


# --------------------------------------------------------------------------- #
# admin invites
# --------------------------------------------------------------------------- #

async def _valid_invite(token: str, session: AsyncSession) -> AuthInvite:
    invite = await session.get(AuthInvite, token)
    if invite is None:
        raise HTTPException(status_code=404, detail="Invite not found")
    if invite.used_at is not None:
        raise HTTPException(status_code=410, detail="Invite already used")
    if _as_utc_naive(invite.expires_at) < _now_naive():
        raise HTTPException(status_code=410, detail="Invite expired")
    return invite


async def _consume_invite_atomically(session: AsyncSession, token: str) -> bool:
    """Atomically mark an invite used via a conditional UPDATE.

    The read-then-check in ``_valid_invite`` is not atomic; two concurrent
    register/complete calls can both observe ``used_at IS NULL``. This single
    ``UPDATE ... WHERE token = :token AND used_at IS NULL`` makes the claim
    atomic: exactly one caller gets ``rowcount == 1``. Does NOT commit — the
    caller owns the surrounding transaction (so a failed claim can roll back a
    half-built credential).
    """
    result = await session.execute(
        update(AuthInvite)
        .where(AuthInvite.token == token, AuthInvite.used_at.is_(None))
        .values(used_at=_now_naive())
    )
    return result.rowcount == 1


@router.get("/invites/{token}")
async def peek_invite(token: str, session: AsyncSession = Depends(get_session)) -> dict[str, Any]:
    _require_local_auth()
    invite = await session.get(AuthInvite, token)
    if invite is None:
        raise HTTPException(status_code=404, detail="Invite not found")
    return {
        "email": invite.email,
        "used": invite.used_at is not None,
        "expired": _as_utc_naive(invite.expires_at) < _now_naive(),
    }


@router.get("/invites")
async def list_invites(
    _admin: UserProfile = Depends(require_admin_user),
    session: AsyncSession = Depends(get_session),
) -> list[dict[str, Any]]:
    _require_local_auth()
    result = await session.execute(select(AuthInvite).order_by(AuthInvite.created_at.desc()))
    invites = result.scalars().all()
    return [_invite_dict(i) for i in invites]


@router.post("/invites", status_code=201)
async def create_invite(
    request: Request,
    payload: dict[str, str],
    admin: UserProfile = Depends(require_admin_user),
    session: AsyncSession = Depends(get_session),
) -> dict[str, Any]:
    _require_local_auth()
    email = (payload.get("email") or "").strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Invalid email")

    invite = AuthInvite(
        token=secrets.token_urlsafe(32),
        email=email,
        role=payload.get("role") or "viewer",
        created_by=admin.id if admin else None,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=settings.invite_ttl_seconds),
    )
    session.add(invite)
    await session.commit()
    return _invite_dict(invite)


@router.delete("/invites/{token}", status_code=204)
async def revoke_invite(
    token: str,
    _admin: UserProfile = Depends(require_admin_user),
    session: AsyncSession = Depends(get_session),
) -> None:
    _require_local_auth()
    invite = await session.get(AuthInvite, token)
    if invite is None:
        raise HTTPException(status_code=404, detail="Invite not found")
    await session.delete(invite)
    await session.commit()


# --------------------------------------------------------------------------- #
# serialization
# --------------------------------------------------------------------------- #

def _profile_dict(profile: UserProfile | None) -> dict[str, Any]:
    if profile is None:
        return {"id": None, "email": "", "displayName": "", "avatarUrl": ""}
    return {
        "id": str(profile.id),
        "email": profile.email,
        "displayName": profile.display_name,
        "avatarUrl": profile.avatar_url,
    }


def _invite_dict(invite: AuthInvite) -> dict[str, Any]:
    return {
        "token": invite.token,
        "email": invite.email,
        "role": invite.role,
        "createdBy": str(invite.created_by) if invite.created_by else None,
        "expiresAt": invite.expires_at.isoformat(),
        "usedAt": invite.used_at.isoformat() if invite.used_at else None,
        "createdAt": invite.created_at.isoformat(),
    }
