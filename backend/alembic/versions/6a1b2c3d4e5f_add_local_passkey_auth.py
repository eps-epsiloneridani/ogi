"""add local passkey-auth tables

Backs the fork's local (passkey-first) auth mode: per-user password hashes
(optional argon2 fallback), WebAuthn credentials, admin-minted one-time invites,
and short-lived in-flight WebAuthn challenges. Only exercised when local auth
is enabled (Supabase absent + OGI_LOCAL_AUTH_ENABLED=true).

Revision ID: 6a1b2c3d4e5f
Revises: d8e1f2a3b4c5
Create Date: 2026-10-25 00:00:00
"""
from alembic import op
import sqlalchemy as sa
import sqlmodel


revision = "6a1b2c3d4e5f"
down_revision = "d8e1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "local_auth_users",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("password_hash", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("user_id"),
    )

    op.create_table(
        "webauthn_credentials",
        sa.Column("credential_id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("public_key", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("sign_count", sa.Integer(), nullable=False),
        sa.Column("transports", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("aaguid", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("credential_id"),
    )
    op.create_index(
        "ix_webauthn_credentials_user_id", "webauthn_credentials", ["user_id"]
    )

    op.create_table(
        "auth_invites",
        sa.Column("token", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("email", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("role", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("created_by", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("token"),
    )
    op.create_index("ix_auth_invites_email", "auth_invites", ["email"])

    op.create_table(
        "webauthn_challenges",
        sa.Column("id", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("challenge", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("kind", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("webauthn_challenges")
    op.drop_table("auth_invites")
    op.drop_table("webauthn_credentials")
    op.drop_table("local_auth_users")
