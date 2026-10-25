"""Local (passkey-first) auth tables.

These back the fork's passwordless WebAuthn login, admin-minted invites, the
first-run bootstrap, and the optional argon2 password fallback. They are only
used when ``settings.auth_mode == "local"``; the canonical user identity stays
in the existing ``profiles`` table (``UserProfile``).
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from sqlmodel import SQLModel, Field, Column, DateTime


class LocalAuthUser(SQLModel, table=True):
    __tablename__ = "local_auth_users"

    user_id: UUID = Field(primary_key=True, foreign_key="profiles.id", ondelete="CASCADE")
    password_hash: str | None = Field(default=None, nullable=True)
    # TOTP second factor. ``totp_secret`` holds the base32 secret once an
    # enrollment is *pending* or *complete*; ``totp_enrolled_at`` is only set
    # once the user has verified a code, i.e. the factor is live.
    totp_secret: str | None = Field(default=None, nullable=True)
    totp_enrolled_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )


class WebAuthnCredential(SQLModel, table=True):
    __tablename__ = "webauthn_credentials"

    # base64url-encoded credential ID (unique per authenticator)
    credential_id: str = Field(primary_key=True)
    user_id: UUID = Field(foreign_key="profiles.id", ondelete="CASCADE", index=True)
    public_key: str = ""  # base64url-encoded COSE public key
    sign_count: int = 0
    transports: str = "[]"  # JSON array of transport hints
    aaguid: str = ""
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
    last_used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )


class AuthInvite(SQLModel, table=True):
    __tablename__ = "auth_invites"

    token: str = Field(primary_key=True)  # opaque random token handed to the invitee offline
    email: str = Field(index=True)
    role: str = "viewer"  # reserved for future project-role wiring; admin gating uses OGI_ADMIN_EMAILS
    created_by: UUID | None = Field(default=None, nullable=True)
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )


class WebAuthnChallenge(SQLModel, table=True):
    __tablename__ = "webauthn_challenges"

    id: str = Field(primary_key=True)  # random opaque handle returned to the client
    challenge: str = ""  # base64url-encoded challenge bytes
    kind: str = ""  # "registration" | "authentication"
    user_id: UUID | None = Field(default=None, nullable=True)
    expires_at: datetime = Field(sa_column=Column(DateTime(timezone=True)))
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )


class TotpRecoveryCode(SQLModel, table=True):
    """One-time recovery codes for the TOTP second factor.

    Only the SHA-256 digest of each code is stored; the plaintext is shown to
    the user exactly once at enrollment. A code is single-use: on a successful
    login ``used_at`` is stamped and it can never be used again.
    """

    __tablename__ = "totp_recovery_codes"

    code_hash: str = Field(primary_key=True)  # sha256(normalized code) hex
    user_id: UUID = Field(foreign_key="profiles.id", ondelete="CASCADE", index=True)
    used_at: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )


class AuthRateLimit(SQLModel, table=True):
    """DB-backed per-key login rate-limit counter (progressive backoff).

    Keyed by the normalized email so password+OTP brute force is throttled even
    across backend restarts and multiple workers (in-process counters would not
    survive either). ``locked_until`` is set once ``failed_count`` exceeds the
    threshold, with an exponentially growing lockout capped at a ceiling.
    """

    __tablename__ = "auth_rate_limits"

    key: str = Field(primary_key=True)  # normalized email
    failed_count: int = 0
    locked_until: datetime | None = Field(
        default=None, sa_column=Column(DateTime(timezone=True), nullable=True)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column=Column(DateTime(timezone=True)),
    )
