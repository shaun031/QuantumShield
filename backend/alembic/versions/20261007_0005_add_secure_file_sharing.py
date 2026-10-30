"""Add Phase 6 file shares and recipient-specific key envelopes.

Revision ID: 0005_secure_sharing
Revises: 0004_mlkem_keys
Create Date: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0005_secure_sharing"
down_revision: str | Sequence[str] | None = "0004_mlkem_keys"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "file_shares",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_id", sa.Uuid(), nullable=False),
        sa.Column("sender_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_id", sa.Uuid(), nullable=False),
        sa.Column("permission", sa.String(length=16), server_default="READ", nullable=False),
        sa.Column("status", sa.String(length=16), server_default="ACTIVE", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("sender_id != recipient_id", name="ck_file_shares_distinct_users"),
        sa.CheckConstraint("permission = 'READ'", name="ck_file_shares_read_only"),
        sa.CheckConstraint("status = 'ACTIVE'", name="ck_file_shares_active_only"),
        sa.ForeignKeyConstraint(
            ["file_id"], ["files.id"], name="fk_file_shares_file_id_files", ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["sender_id"], ["users.id"], name="fk_file_shares_sender_id_users", ondelete="RESTRICT"
        ),
        sa.ForeignKeyConstraint(
            ["recipient_id"], ["users.id"], name="fk_file_shares_recipient_id_users", ondelete="RESTRICT"
        ),
        sa.PrimaryKeyConstraint("id", name="pk_file_shares"),
        sa.UniqueConstraint("file_id", "recipient_id", name="uq_file_shares_file_recipient"),
    )
    op.create_index(
        "ix_file_shares_recipient_created",
        "file_shares",
        ["recipient_id", "created_at"],
    )
    op.create_index(
        "ix_file_shares_sender_created",
        "file_shares",
        ["sender_id", "created_at"],
    )

    op.create_table(
        "share_crypto_metadata",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("file_share_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_key_id", sa.Uuid(), nullable=False),
        sa.Column("recipient_key_version", sa.SmallInteger(), nullable=False),
        sa.Column("kem_algorithm", sa.String(length=32), nullable=False),
        sa.Column("kem_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("kdf_algorithm", sa.String(length=32), nullable=False),
        sa.Column("kdf_salt", sa.LargeBinary(length=32), nullable=False),
        sa.Column("key_wrap_algorithm", sa.String(length=32), nullable=False),
        sa.Column("wrapped_file_key", sa.LargeBinary(length=48), nullable=False),
        sa.Column("key_wrap_nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column("crypto_version", sa.SmallInteger(), nullable=False),
        sa.Column("aad_version", sa.SmallInteger(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("crypto_version >= 1", name="ck_share_crypto_version_positive"),
        sa.CheckConstraint("aad_version >= 1", name="ck_share_crypto_aad_version_positive"),
        sa.CheckConstraint(
            "recipient_key_version >= 1", name="ck_share_crypto_recipient_key_version_positive"
        ),
        sa.CheckConstraint("length(kdf_salt) = 32", name="ck_share_crypto_kdf_salt_length"),
        sa.CheckConstraint(
            "length(wrapped_file_key) = 48", name="ck_share_crypto_wrapped_key_length"
        ),
        sa.CheckConstraint(
            "length(key_wrap_nonce) = 12", name="ck_share_crypto_wrap_nonce_length"
        ),
        sa.CheckConstraint(
            "kem_algorithm != 'ML-KEM-768' OR length(kem_ciphertext) = 1088",
            name="ck_share_crypto_mlkem768_ciphertext_length",
        ),
        sa.ForeignKeyConstraint(
            ["file_share_id"],
            ["file_shares.id"],
            name="fk_share_crypto_file_share_id_file_shares",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["recipient_key_id"],
            ["user_crypto_keys.id"],
            name="fk_share_crypto_recipient_key_id_user_crypto_keys",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_share_crypto_metadata"),
        sa.UniqueConstraint("file_share_id", name="uq_share_crypto_file_share_id"),
    )


def downgrade() -> None:
    op.drop_table("share_crypto_metadata")
    op.drop_index("ix_file_shares_sender_created", table_name="file_shares")
    op.drop_index("ix_file_shares_recipient_created", table_name="file_shares")
    op.drop_table("file_shares")
