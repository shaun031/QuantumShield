"""Add Phase 7 security levels and multi-ML-KEM constraints.

Revision ID: 0006_multi_mlkem
Revises: 0005_secure_sharing
Create Date: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0006_multi_mlkem"
down_revision: str | Sequence[str] | None = "0005_secure_sharing"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "file_crypto_metadata",
        sa.Column("security_level", sa.String(length=16), nullable=True),
    )
    op.execute(
        "UPDATE file_crypto_metadata SET security_level = 'STANDARD' "
        "WHERE crypto_version = 2 AND kem_algorithm = 'ML-KEM-768'"
    )
    op.add_column(
        "share_crypto_metadata",
        sa.Column("security_level", sa.String(length=16), nullable=True),
    )
    op.execute(
        "UPDATE share_crypto_metadata SET security_level = 'STANDARD' "
        "WHERE kem_algorithm = 'ML-KEM-768'"
    )
    op.alter_column("share_crypto_metadata", "security_level", nullable=False)

    op.drop_constraint(
        "ck_user_crypto_mlkem768_lengths", "user_crypto_keys", type_="check"
    )
    op.create_check_constraint(
        "ck_user_crypto_supported_algorithm",
        "user_crypto_keys",
        "algorithm IN ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024')",
    )
    op.create_check_constraint(
        "ck_user_crypto_mlkem_lengths",
        "user_crypto_keys",
        "(algorithm != 'ML-KEM-512' OR "
        "(length(public_key) = 800 AND length(encrypted_private_key) = 1648)) "
        "AND (algorithm != 'ML-KEM-768' OR "
        "(length(public_key) = 1184 AND length(encrypted_private_key) = 80)) "
        "AND (algorithm != 'ML-KEM-1024' OR "
        "(length(public_key) = 1568 AND length(encrypted_private_key) = 80))",
    )

    op.drop_constraint(
        "ck_file_crypto_mlkem768_ciphertext_length",
        "file_crypto_metadata",
        type_="check",
    )
    op.create_check_constraint(
        "ck_file_crypto_mlkem_ciphertext_length",
        "file_crypto_metadata",
        "kem_algorithm IS NULL OR "
        "(kem_algorithm = 'ML-KEM-512' AND length(kem_ciphertext) = 768) OR "
        "(kem_algorithm = 'ML-KEM-768' AND length(kem_ciphertext) = 1088) OR "
        "(kem_algorithm = 'ML-KEM-1024' AND length(kem_ciphertext) = 1568)",
    )
    op.create_check_constraint(
        "ck_file_crypto_security_algorithm_match",
        "file_crypto_metadata",
        "crypto_version != 2 OR (security_level IS NOT NULL AND ("
        "(security_level = 'LOW' AND kem_algorithm = 'ML-KEM-512') OR "
        "(security_level = 'STANDARD' AND kem_algorithm = 'ML-KEM-768') OR "
        "(security_level = 'HIGH' AND kem_algorithm = 'ML-KEM-1024')))",
    )
    op.drop_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        type_="check",
    )
    op.create_check_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        "crypto_version != 2 OR "
        "(kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
        "AND kdf_algorithm IS NOT NULL AND length(kdf_salt) = 32 "
        "AND recipient_key_id IS NOT NULL AND recipient_key_version IS NOT NULL "
        "AND security_level IS NOT NULL)",
    )

    op.drop_constraint(
        "ck_share_crypto_mlkem768_ciphertext_length",
        "share_crypto_metadata",
        type_="check",
    )
    op.create_check_constraint(
        "ck_share_crypto_mlkem_ciphertext_length",
        "share_crypto_metadata",
        "(kem_algorithm = 'ML-KEM-512' AND length(kem_ciphertext) = 768) OR "
        "(kem_algorithm = 'ML-KEM-768' AND length(kem_ciphertext) = 1088) OR "
        "(kem_algorithm = 'ML-KEM-1024' AND length(kem_ciphertext) = 1568)",
    )
    op.create_check_constraint(
        "ck_share_crypto_security_algorithm_match",
        "share_crypto_metadata",
        "(security_level = 'LOW' AND kem_algorithm = 'ML-KEM-512') OR "
        "(security_level = 'STANDARD' AND kem_algorithm = 'ML-KEM-768') OR "
        "(security_level = 'HIGH' AND kem_algorithm = 'ML-KEM-1024')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_share_crypto_security_algorithm_match",
        "share_crypto_metadata",
        type_="check",
    )
    op.drop_constraint(
        "ck_share_crypto_mlkem_ciphertext_length",
        "share_crypto_metadata",
        type_="check",
    )
    op.create_check_constraint(
        "ck_share_crypto_mlkem768_ciphertext_length",
        "share_crypto_metadata",
        "kem_algorithm != 'ML-KEM-768' OR length(kem_ciphertext) = 1088",
    )

    op.drop_constraint(
        "ck_file_crypto_security_algorithm_match",
        "file_crypto_metadata",
        type_="check",
    )
    op.drop_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        type_="check",
    )
    op.create_check_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        "crypto_version != 2 OR "
        "(kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
        "AND kdf_algorithm IS NOT NULL AND length(kdf_salt) = 32 "
        "AND recipient_key_id IS NOT NULL AND recipient_key_version IS NOT NULL)",
    )
    op.drop_constraint(
        "ck_file_crypto_mlkem_ciphertext_length",
        "file_crypto_metadata",
        type_="check",
    )
    op.create_check_constraint(
        "ck_file_crypto_mlkem768_ciphertext_length",
        "file_crypto_metadata",
        "kem_algorithm IS NULL OR kem_algorithm != 'ML-KEM-768' "
        "OR length(kem_ciphertext) = 1088",
    )

    op.drop_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys", type_="check")
    op.drop_constraint(
        "ck_user_crypto_supported_algorithm", "user_crypto_keys", type_="check"
    )
    op.create_check_constraint(
        "ck_user_crypto_mlkem768_lengths",
        "user_crypto_keys",
        "algorithm != 'ML-KEM-768' OR "
        "(length(public_key) = 1184 AND length(encrypted_private_key) = 80)",
    )
    op.drop_column("share_crypto_metadata", "security_level")
    op.drop_column("file_crypto_metadata", "security_level")
