"""add TOTP second factor + recovery codes + login rate limits

Extends the local-auth fallback so password login can require a TOTP second
factor (or a one-time recovery code) and is throttled with a DB-backed
per-email rate limiter. Adds two nullable columns to ``local_auth_users``
(totp_secret, totp_enrolled_at) and two new tables: ``totp_recovery_codes``
(single-use, hashed) and ``auth_rate_limits`` (progressive backoff).

Revision ID: 9c7d2e5f1a3b
Revises: 6a1b2c3d4e5f
Create Date: 2026-10-25 00:00:00
"""
from alembic import op
import sqlalchemy as sa
import sqlmodel


revision = "9c7d2e5f1a3b"
down_revision = "6a1b2c3d4e5f"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "local_auth_users",
        sa.Column("totp_secret", sqlmodel.sql.sqltypes.AutoString(), nullable=True),
    )
    op.add_column(
        "local_auth_users",
        sa.Column("totp_enrolled_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "totp_recovery_codes",
        sa.Column("code_hash", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["profiles.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("code_hash"),
    )
    op.create_index("ix_totp_recovery_codes_user_id", "totp_recovery_codes", ["user_id"])

    op.create_table(
        "auth_rate_limits",
        sa.Column("key", sqlmodel.sql.sqltypes.AutoString(), nullable=False),
        sa.Column("failed_count", sa.Integer(), nullable=False),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("key"),
    )


def downgrade() -> None:
    op.drop_table("auth_rate_limits")
    op.drop_index("ix_totp_recovery_codes_user_id", table_name="totp_recovery_codes")
    op.drop_table("totp_recovery_codes")
    op.drop_column("local_auth_users", "totp_enrolled_at")
    op.drop_column("local_auth_users", "totp_secret")
