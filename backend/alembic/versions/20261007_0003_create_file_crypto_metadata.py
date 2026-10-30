"""Create file crypto metadata table.

Revision ID: 0003_file_crypto
Revises: 0002_create_files
Create Date: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0003_file_crypto"
down_revision: str | Sequence[str] | None = "0002_create_files"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "file_crypto_metadata",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("content_algorithm", sa.String(length=32), nullable=False),
        sa.Column("content_nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("wrapped_file_key", sa.LargeBinary(length=48), nullable=False),
        sa.Column("key_wrap_algorithm", sa.String(length=32), nullable=False),
        sa.Column("key_wrap_nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("crypto_version", sa.SmallInteger(), nullable=False),
        sa.Column("aad_version", sa.SmallInteger(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "aad_version >= 1",
            name="ck_file_crypto_aad_version_positive",
        ),
        sa.CheckConstraint(
            "crypto_version >= 1",
            name="ck_file_crypto_version_positive",
        ),
        sa.CheckConstraint(
            "length(content_nonce) = 12",
            name="ck_file_crypto_content_nonce_length",
        ),
        sa.CheckConstraint(
            "length(wrapped_file_key) = 48",
            name="ck_file_crypto_wrapped_key_length",
        ),
        sa.CheckConstraint(
            "length(key_wrap_nonce) = 12",
            name="ck_file_crypto_wrap_nonce_length",
        ),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.id"],
            name="fk_file_crypto_metadata_file_id_files",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_file_crypto_metadata"),
        sa.UniqueConstraint("file_id", name="uq_file_crypto_metadata_file_id"),
    )


def downgrade() -> None:
    op.drop_table("file_crypto_metadata")
