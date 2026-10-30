"""Add Phase 5 ML-KEM user keys and file-key envelope metadata.

Revision ID: 0004_mlkem_keys
Revises: 0003_file_crypto
Create Date: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0004_mlkem_keys"
down_revision: str | Sequence[str] | None = "0003_file_crypto"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user_crypto_keys",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("algorithm", sa.String(length=32), nullable=False),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=False),
        sa.Column("private_key_nonce", sa.LargeBinary(length=12), nullable=False),
        sa.Column(
            "private_key_protection_algorithm",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "private_key_protection_version",
            sa.SmallInteger(),
            nullable=False,
        ),
        sa.Column("key_version", sa.SmallInteger(), nullable=False),
        sa.Column(
            "is_active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(encrypted_private_key) > 16",
            name="ck_user_crypto_encrypted_private_key_present",
        ),
        sa.CheckConstraint(
            "key_version >= 1",
            name="ck_user_crypto_key_version_positive",
        ),
        sa.CheckConstraint(
            "private_key_protection_version >= 1",
            name="ck_user_crypto_protection_version_positive",
        ),
        sa.CheckConstraint(
            "length(private_key_nonce) = 12",
            name="ck_user_crypto_private_nonce_length",
        ),
        sa.CheckConstraint(
            "length(public_key) > 0",
            name="ck_user_crypto_public_key_present",
        ),
        sa.CheckConstraint(
            "algorithm != 'ML-KEM-768' OR "
            "(length(public_key) = 1184 AND length(encrypted_private_key) = 80)",
            name="ck_user_crypto_mlkem768_lengths",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_user_crypto_keys_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_user_crypto_keys"),
        sa.UniqueConstraint(
            "user_id",
            "algorithm",
            "key_version",
            name="uq_user_crypto_keys_user_algorithm_version",
        ),
    )
    op.create_index(
        "ix_user_crypto_keys_user_active",
        "user_crypto_keys",
        ["user_id", "algorithm", "is_active"],
        unique=False,
    )

    op.add_column(
        "file_crypto_metadata",
        sa.Column("kem_algorithm", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "file_crypto_metadata",
        sa.Column("kem_ciphertext", sa.LargeBinary(), nullable=True),
    )
    op.add_column(
        "file_crypto_metadata",
        sa.Column("kdf_algorithm", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "file_crypto_metadata",
        sa.Column("kdf_salt", sa.LargeBinary(length=32), nullable=True),
    )
    op.add_column(
        "file_crypto_metadata",
        sa.Column("recipient_key_id", sa.Uuid(), nullable=True),
    )
    op.add_column(
        "file_crypto_metadata",
        sa.Column("recipient_key_version", sa.SmallInteger(), nullable=True),
    )
    op.create_foreign_key(
        "fk_file_crypto_metadata_recipient_key_id_user_crypto_keys",
        "file_crypto_metadata",
        "user_crypto_keys",
        ["recipient_key_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_check_constraint(
        "ck_file_crypto_recipient_key_version_positive",
        "file_crypto_metadata",
        "recipient_key_version IS NULL OR recipient_key_version >= 1",
    )
    op.create_check_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        "crypto_version != 2 OR "
        "(kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
        "AND kdf_algorithm IS NOT NULL AND length(kdf_salt) = 32 "
        "AND recipient_key_id IS NOT NULL "
        "AND recipient_key_version IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_file_crypto_mlkem768_ciphertext_length",
        "file_crypto_metadata",
        "kem_algorithm IS NULL OR kem_algorithm != 'ML-KEM-768' "
        "OR length(kem_ciphertext) = 1088",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_file_crypto_mlkem768_ciphertext_length",
        "file_crypto_metadata",
        type_="check",
    )
    op.drop_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        type_="check",
    )
    op.drop_constraint(
        "ck_file_crypto_recipient_key_version_positive",
        "file_crypto_metadata",
        type_="check",
    )
    op.drop_constraint(
        "fk_file_crypto_metadata_recipient_key_id_user_crypto_keys",
        "file_crypto_metadata",
        type_="foreignkey",
    )
    op.drop_column("file_crypto_metadata", "recipient_key_version")
    op.drop_column("file_crypto_metadata", "recipient_key_id")
    op.drop_column("file_crypto_metadata", "kdf_salt")
    op.drop_column("file_crypto_metadata", "kdf_algorithm")
    op.drop_column("file_crypto_metadata", "kem_ciphertext")
    op.drop_column("file_crypto_metadata", "kem_algorithm")

    op.drop_index("ix_user_crypto_keys_user_active", table_name="user_crypto_keys")
    op.drop_table("user_crypto_keys")
