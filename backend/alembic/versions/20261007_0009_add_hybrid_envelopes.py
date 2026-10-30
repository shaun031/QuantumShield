"""Add X25519 user keys and versioned hybrid file/share envelopes.

Revision ID: 0009_hybrid_envelopes
Revises: 0008_crypto_suites
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0009_hybrid_envelopes"
down_revision: str | Sequence[str] | None = "0008_crypto_suites"
branch_labels = None
depends_on = None

_level_match = "((security_level='LOW' AND kem_algorithm='ML-KEM-512') OR (security_level='STANDARD' AND kem_algorithm='ML-KEM-768') OR (security_level='HIGH' AND kem_algorithm='ML-KEM-1024'))"


def _suite_match(file: bool, architectures: tuple[str, ...] = ("PQ", "HYBRID")) -> str:
    clauses = []
    for architecture in architectures:
        for level, size in (("LOW", 512), ("STANDARD", 768), ("HIGH", 1024)):
            extra = "AND content_algorithm = 'AES-256-GCM' " if file else ""
            clauses.append(
                f"(crypto_suite_id = 'QS-{architecture}-{size}-V1' "
                f"AND security_level = '{level}' AND kem_algorithm = 'ML-KEM-{size}' "
                f"{extra}AND kdf_algorithm = 'HKDF-SHA256' "
                "AND key_wrap_algorithm = 'KEK-AES-256-GCM')"
            )
    return ("crypto_suite_id IS NULL OR " if file else "") + " OR ".join(clauses)


def upgrade() -> None:
    op.drop_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys", type_="check")
    op.drop_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys", type_="check")
    op.create_check_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys",
        "algorithm IN ('ML-KEM-512','ML-KEM-768','ML-KEM-1024','X25519')")
    op.create_check_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys",
        "(algorithm != 'ML-KEM-512' OR (length(public_key)=800 AND length(encrypted_private_key)=1648)) "
        "AND (algorithm != 'ML-KEM-768' OR (length(public_key)=1184 AND length(encrypted_private_key)=80)) "
        "AND (algorithm != 'ML-KEM-1024' OR (length(public_key)=1568 AND length(encrypted_private_key)=80)) "
        "AND (algorithm != 'X25519' OR (length(public_key)=32 AND length(encrypted_private_key)=48))")
    for table in ("file_crypto_metadata", "share_crypto_metadata"):
        op.add_column(table, sa.Column("security_architecture", sa.String(16), nullable=False, server_default="PQ_ONLY"))
        op.add_column(table, sa.Column("classical_algorithm", sa.String(32)))
        op.add_column(table, sa.Column("ephemeral_public_key", sa.LargeBinary(32)))
        op.add_column(table, sa.Column("recipient_classical_key_id", sa.Uuid(as_uuid=True)))
        op.add_column(table, sa.Column("recipient_classical_key_version", sa.SmallInteger()))
        op.add_column(table, sa.Column("combiner_version", sa.SmallInteger()))
        op.create_foreign_key(f"fk_{table}_classical_key", table, "user_crypto_keys", ["recipient_classical_key_id"], ["id"], ondelete="RESTRICT")
        op.create_check_constraint(f"ck_{'file' if table.startswith('file') else 'share'}_crypto_architecture", table,
            "security_architecture IN ('PQ_ONLY','HYBRID')")
    op.drop_constraint("ck_file_crypto_kem_metadata_present", "file_crypto_metadata", type_="check")
    op.drop_constraint("ck_file_crypto_security_algorithm_match", "file_crypto_metadata", type_="check")
    op.drop_constraint("ck_file_crypto_suite_algorithm_match", "file_crypto_metadata", type_="check")
    op.create_check_constraint("ck_file_crypto_kem_metadata_present", "file_crypto_metadata",
        "crypto_version NOT IN (2,3,4) OR (kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
        "AND kdf_algorithm IS NOT NULL AND length(kdf_salt)=32 AND recipient_key_id IS NOT NULL "
        "AND recipient_key_version IS NOT NULL AND security_level IS NOT NULL)")
    op.create_check_constraint("ck_file_crypto_security_algorithm_match", "file_crypto_metadata",
        "crypto_version NOT IN (2,3,4) OR (security_level IS NOT NULL AND " + _level_match + ")")
    op.create_check_constraint("ck_file_crypto_suite_algorithm_match", "file_crypto_metadata", _suite_match(True))
    op.drop_constraint("ck_share_crypto_suite_algorithm_match", "share_crypto_metadata", type_="check")
    op.create_check_constraint("ck_share_crypto_suite_algorithm_match", "share_crypto_metadata", _suite_match(False))
    for table, short, hybrid_version in (("file_crypto_metadata", "file", 4), ("share_crypto_metadata", "share", 3)):
        op.create_check_constraint(f"ck_{short}_crypto_hybrid_metadata", table,
            f"(crypto_version={hybrid_version} AND aad_version={hybrid_version} AND security_architecture='HYBRID' "
            "AND classical_algorithm='X25519' AND length(ephemeral_public_key)=32 "
            "AND recipient_classical_key_id IS NOT NULL AND recipient_classical_key_version>=1 "
            "AND combiner_version=1 AND crypto_suite_id LIKE 'QS-HYBRID-%') OR "
            f"(crypto_version!={hybrid_version} AND security_architecture='PQ_ONLY' "
            "AND classical_algorithm IS NULL AND ephemeral_public_key IS NULL "
            "AND recipient_classical_key_id IS NULL AND recipient_classical_key_version IS NULL "
            "AND combiner_version IS NULL AND (crypto_suite_id IS NULL OR crypto_suite_id LIKE 'QS-PQ-%'))")


def downgrade() -> None:
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM user_crypto_keys WHERE algorithm='X25519') "
               "OR EXISTS (SELECT 1 FROM file_crypto_metadata WHERE crypto_version=4) "
               "OR EXISTS (SELECT 1 FROM share_crypto_metadata WHERE crypto_version=3) "
               "THEN RAISE EXCEPTION 'Hybrid records must be preserved before downgrade'; END IF; END $$")
    for table, short in (("file_crypto_metadata", "file"), ("share_crypto_metadata", "share")):
        op.drop_constraint(f"ck_{short}_crypto_hybrid_metadata", table, type_="check")
        op.drop_constraint(f"ck_{short}_crypto_architecture", table, type_="check")
        op.drop_constraint(f"fk_{table}_classical_key", table, type_="foreignkey")
        for col in ("combiner_version", "recipient_classical_key_version", "recipient_classical_key_id", "ephemeral_public_key", "classical_algorithm", "security_architecture"):
            op.drop_column(table, col)
    op.drop_constraint("ck_share_crypto_suite_algorithm_match", "share_crypto_metadata", type_="check")
    op.drop_constraint("ck_file_crypto_suite_algorithm_match", "file_crypto_metadata", type_="check")
    op.drop_constraint("ck_file_crypto_security_algorithm_match", "file_crypto_metadata", type_="check")
    op.drop_constraint("ck_file_crypto_kem_metadata_present", "file_crypto_metadata", type_="check")
    op.create_check_constraint("ck_share_crypto_suite_algorithm_match", "share_crypto_metadata", _suite_match(False, ("PQ",)))
    op.create_check_constraint("ck_file_crypto_suite_algorithm_match", "file_crypto_metadata", _suite_match(True, ("PQ",)))
    op.create_check_constraint("ck_file_crypto_kem_metadata_present", "file_crypto_metadata",
        "crypto_version NOT IN (2,3) OR (kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
        "AND kdf_algorithm IS NOT NULL AND length(kdf_salt)=32 AND recipient_key_id IS NOT NULL "
        "AND recipient_key_version IS NOT NULL AND security_level IS NOT NULL)")
    op.create_check_constraint("ck_file_crypto_security_algorithm_match", "file_crypto_metadata",
        "crypto_version NOT IN (2,3) OR (security_level IS NOT NULL AND " + _level_match + ")")
    op.drop_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys", type_="check")
    op.drop_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys", type_="check")
    op.create_check_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys", "algorithm IN ('ML-KEM-512','ML-KEM-768','ML-KEM-1024')")
    op.create_check_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys",
        "(algorithm != 'ML-KEM-512' OR (length(public_key)=800 AND length(encrypted_private_key)=1648)) "
        "AND (algorithm != 'ML-KEM-768' OR (length(public_key)=1184 AND length(encrypted_private_key)=80)) "
        "AND (algorithm != 'ML-KEM-1024' OR (length(public_key)=1568 AND length(encrypted_private_key)=80))")
