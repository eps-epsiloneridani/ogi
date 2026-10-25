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

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

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
    LocalAuthUser,
    UserProfile,
    WebAuthnChallenge,
    WebAuthnCredential,
)

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


async def _has_any_local_user(session: AsyncSession) -> bool:
    result = await session.execute(select(LocalAuthUser.user_id).limit(1))
    return result.scalar_one_or_none() is not None


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
        "rpid": rpid,
        "origins": origins,
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
        invite.used_at = datetime.now(timezone.utc)
        session.add(invite)
    await session.commit()

    profile = await session.get(UserProfile, user_id)
    token = issue_session_token(user_id)
    _set_session_cookie(response, token)
    return {"user": _profile_dict(profile), "token": token}


# --------------------------------------------------------------------------- #
# passkey login
# --------------------------------------------------------------------------- #

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
# password fallback (env-gated, OFF by default)
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
    profile = await _get_or_create_profile(email, session)
    local_user = await session.get(LocalAuthUser, profile.id)
    if local_user is None or not local_user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    try:
        _ph.verify(local_user.password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        raise HTTPException(status_code=401, detail="Invalid credentials")

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
    if local_user is None:
        local_user = LocalAuthUser(user_id=profile.id)
        session.add(local_user)
    local_user.password_hash = _ph.hash(password)
    await session.commit()
    return {"ok": True}


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
