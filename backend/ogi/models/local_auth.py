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
