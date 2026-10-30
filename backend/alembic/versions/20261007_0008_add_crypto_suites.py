"""Add Phase 9 crypto-suite identifiers and validation.

Revision ID: 0008_crypto_suites
Revises: 0007_adaptive_policy
Create Date: 2026-10-07
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


revision: str = "0008_crypto_suites"
down_revision: str | Sequence[str] | None = "0007_adaptive_policy"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


SUITE_CASE = (
    "CASE kem_algorithm "
    "WHEN 'ML-KEM-512' THEN 'QS-PQ-512-V1' "
    "WHEN 'ML-KEM-768' THEN 'QS-PQ-768-V1' "
    "WHEN 'ML-KEM-1024' THEN 'QS-PQ-1024-V1' END"
)

FILE_SUITE_MATCH = (
    "crypto_suite_id IS NULL OR "
    "(crypto_suite_id = 'QS-PQ-512-V1' AND security_level = 'LOW' "
    "AND kem_algorithm = 'ML-KEM-512' AND content_algorithm = 'AES-256-GCM' "
    "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
    "(crypto_suite_id = 'QS-PQ-768-V1' AND security_level = 'STANDARD' "
    "AND kem_algorithm = 'ML-KEM-768' AND content_algorithm = 'AES-256-GCM' "
    "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
    "(crypto_suite_id = 'QS-PQ-1024-V1' AND security_level = 'HIGH' "
    "AND kem_algorithm = 'ML-KEM-1024' AND content_algorithm = 'AES-256-GCM' "
    "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM')"
)

SHARE_SUITE_MATCH = (
    "(crypto_suite_id = 'QS-PQ-512-V1' AND security_level = 'LOW' "
    "AND kem_algorithm = 'ML-KEM-512' AND kdf_algorithm = 'HKDF-SHA256' "
    "AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
    "(crypto_suite_id = 'QS-PQ-768-V1' AND security_level = 'STANDARD' "
    "AND kem_algorithm = 'ML-KEM-768' AND kdf_algorithm = 'HKDF-SHA256' "
    "AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
    "(crypto_suite_id = 'QS-PQ-1024-V1' AND security_level = 'HIGH' "
    "AND kem_algorithm = 'ML-KEM-1024' AND kdf_algorithm = 'HKDF-SHA256' "
    "AND key_wrap_algorithm = 'KEK-AES-256-GCM')"
)


def upgrade() -> None:
    op.add_column(
        "file_crypto_metadata",
        sa.Column("crypto_suite_id", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "file_crypto_metadata",
        sa.Column("crypto_suite_version", sa.SmallInteger(), nullable=True),
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM file_crypto_metadata "
        "WHERE crypto_version = 2 AND NOT ("
        "content_algorithm = 'AES-256-GCM' AND "
        "key_wrap_algorithm = 'KEK-AES-256-GCM' AND "
        "kdf_algorithm = 'HKDF-SHA256' AND ("
        "(kem_algorithm = 'ML-KEM-512' AND security_level = 'LOW') OR "
        "(kem_algorithm = 'ML-KEM-768' AND security_level = 'STANDARD') OR "
        "(kem_algorithm = 'ML-KEM-1024' AND security_level = 'HIGH')))) "
        "THEN RAISE EXCEPTION 'Phase 9 file suite backfill is ambiguous'; "
        "END IF; END $$"
    )
    op.execute(
        f"UPDATE file_crypto_metadata SET crypto_suite_id = {SUITE_CASE}, "
        "crypto_suite_version = 1 WHERE crypto_version = 2"
    )

    op.add_column(
        "share_crypto_metadata",
        sa.Column("crypto_suite_id", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "share_crypto_metadata",
        sa.Column("crypto_suite_version", sa.SmallInteger(), nullable=True),
    )
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM share_crypto_metadata "
        "WHERE NOT (key_wrap_algorithm = 'KEK-AES-256-GCM' AND "
        "kdf_algorithm = 'HKDF-SHA256' AND ("
        "(kem_algorithm = 'ML-KEM-512' AND security_level = 'LOW') OR "
        "(kem_algorithm = 'ML-KEM-768' AND security_level = 'STANDARD') OR "
        "(kem_algorithm = 'ML-KEM-1024' AND security_level = 'HIGH')))) "
        "THEN RAISE EXCEPTION 'Phase 9 share suite backfill is ambiguous'; "
        "END IF; END $$"
    )
    op.execute(
        f"UPDATE share_crypto_metadata SET crypto_suite_id = {SUITE_CASE}, "
        "crypto_suite_version = 1"
    )
    op.alter_column("share_crypto_metadata", "crypto_suite_id", nullable=False)
    op.alter_column("share_crypto_metadata", "crypto_suite_version", nullable=False)

    op.drop_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        type_="check",
    )
    op.drop_constraint(
        "ck_file_crypto_security_algorithm_match",
        "file_crypto_metadata",
        type_="check",
    )
    op.create_check_constraint(
        "ck_file_crypto_kem_metadata_present",
        "file_crypto_metadata",
        "crypto_version NOT IN (2, 3) OR "
        "(kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
        "AND kdf_algorithm IS NOT NULL AND length(kdf_salt) = 32 "
        "AND recipient_key_id IS NOT NULL AND recipient_key_version IS NOT NULL "
        "AND security_level IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_file_crypto_security_algorithm_match",
        "file_crypto_metadata",
        "crypto_version NOT IN (2, 3) OR (security_level IS NOT NULL AND ("
        "(security_level = 'LOW' AND kem_algorithm = 'ML-KEM-512') OR "
        "(security_level = 'STANDARD' AND kem_algorithm = 'ML-KEM-768') OR "
        "(security_level = 'HIGH' AND kem_algorithm = 'ML-KEM-1024')))",
    )
    op.create_check_constraint(
        "ck_file_crypto_suite_metadata_present",
        "file_crypto_metadata",
        "crypto_version = 1 OR (crypto_suite_id IS NOT NULL AND crypto_suite_version = 1)",
    )
    op.create_check_constraint(
        "ck_file_crypto_suite_algorithm_match",
        "file_crypto_metadata",
        FILE_SUITE_MATCH,
    )
    op.create_check_constraint(
        "ck_share_crypto_suite_version",
        "share_crypto_metadata",
        "crypto_suite_version = 1",
    )
    op.create_check_constraint(
        "ck_share_crypto_suite_algorithm_match",
        "share_crypto_metadata",
        SHARE_SUITE_MATCH,
    )


def downgrade() -> None:
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM file_crypto_metadata "
        "WHERE crypto_version = 3) OR EXISTS "
        "(SELECT 1 FROM share_crypto_metadata WHERE crypto_version = 2) "
        "THEN RAISE EXCEPTION 'Phase 9 records must be preserved before downgrade'; "
        "END IF; END $$"
    )
    op.drop_constraint(
        "ck_share_crypto_suite_algorithm_match", "share_crypto_metadata", type_="check"
    )
    op.drop_constraint(
        "ck_share_crypto_suite_version", "share_crypto_metadata", type_="check"
    )
    op.drop_constraint(
        "ck_file_crypto_suite_algorithm_match", "file_crypto_metadata", type_="check"
    )
    op.drop_constraint(
        "ck_file_crypto_suite_metadata_present", "file_crypto_metadata", type_="check"
    )
    op.drop_constraint(
        "ck_file_crypto_security_algorithm_match", "file_crypto_metadata", type_="check"
    )
    op.drop_constraint(
        "ck_file_crypto_kem_metadata_present", "file_crypto_metadata", type_="check"
    )
    op.create_check_constraint(
        "ck_file_crypto_v2_kem_metadata_present",
        "file_crypto_metadata",
        "crypto_version != 2 OR (kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
        "AND kdf_algorithm IS NOT NULL AND length(kdf_salt) = 32 "
        "AND recipient_key_id IS NOT NULL AND recipient_key_version IS NOT NULL "
        "AND security_level IS NOT NULL)",
    )
    op.create_check_constraint(
        "ck_file_crypto_security_algorithm_match",
        "file_crypto_metadata",
        "crypto_version != 2 OR (security_level IS NOT NULL AND ("
        "(security_level = 'LOW' AND kem_algorithm = 'ML-KEM-512') OR "
        "(security_level = 'STANDARD' AND kem_algorithm = 'ML-KEM-768') OR "
        "(security_level = 'HIGH' AND kem_algorithm = 'ML-KEM-1024')))",
    )
    op.drop_column("share_crypto_metadata", "crypto_suite_version")
    op.drop_column("share_crypto_metadata", "crypto_suite_id")
    op.drop_column("file_crypto_metadata", "crypto_suite_version")
    op.drop_column("file_crypto_metadata", "crypto_suite_id")
