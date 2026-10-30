"""Purpose-separated ML-DSA keys and signed file/share packages.

Revision ID: 0010_digital_signatures
Revises: 0009_hybrid_envelopes
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "0010_digital_signatures"
down_revision: str | Sequence[str] | None = "0009_hybrid_envelopes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("user_crypto_keys", sa.Column("key_purpose", sa.String(16), nullable=False, server_default="KEM"))
    op.execute("UPDATE user_crypto_keys SET key_purpose='KEY_AGREEMENT' WHERE algorithm='X25519'")
    op.drop_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys", type_="check")
    op.drop_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys", type_="check")
    op.create_check_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys",
        "algorithm IN ('ML-KEM-512','ML-KEM-768','ML-KEM-1024','X25519','ML-DSA-44','ML-DSA-65','ML-DSA-87')")
    op.create_check_constraint("ck_user_crypto_key_purpose_algorithm", "user_crypto_keys",
        "(key_purpose='KEM' AND algorithm IN ('ML-KEM-512','ML-KEM-768','ML-KEM-1024')) OR "
        "(key_purpose='KEY_AGREEMENT' AND algorithm='X25519') OR "
        "(key_purpose='SIGNATURE' AND algorithm IN ('ML-DSA-44','ML-DSA-65','ML-DSA-87'))")
    op.create_check_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys",
        "(algorithm!='ML-KEM-512' OR (length(public_key)=800 AND length(encrypted_private_key)=1648)) AND "
        "(algorithm!='ML-KEM-768' OR (length(public_key)=1184 AND length(encrypted_private_key)=80)) AND "
        "(algorithm!='ML-KEM-1024' OR (length(public_key)=1568 AND length(encrypted_private_key)=80)) AND "
        "(algorithm!='X25519' OR (length(public_key)=32 AND length(encrypted_private_key)=48)) AND "
        "(algorithm!='ML-DSA-44' OR (length(public_key)=1312 AND length(encrypted_private_key)=48)) AND "
        "(algorithm!='ML-DSA-65' OR (length(public_key)=1952 AND length(encrypted_private_key)=48)) AND "
        "(algorithm!='ML-DSA-87' OR (length(public_key)=2592 AND length(encrypted_private_key)=48))")

    op.add_column("files", sa.Column("signature_required", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("file_shares", sa.Column("signature_required", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_table(
        "digital_signatures",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True),
        sa.Column("file_id", sa.Uuid(as_uuid=True), sa.ForeignKey("files.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file_share_id", sa.Uuid(as_uuid=True), sa.ForeignKey("file_shares.id", ondelete="CASCADE")),
        sa.Column("signer_user_id", sa.Uuid(as_uuid=True), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("signing_key_id", sa.Uuid(as_uuid=True), sa.ForeignKey("user_crypto_keys.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("signing_key_version", sa.SmallInteger(), nullable=False),
        sa.Column("algorithm", sa.String(32), nullable=False),
        sa.Column("profile_id", sa.String(32), nullable=False),
        sa.Column("payload_version", sa.SmallInteger(), nullable=False),
        sa.Column("scope", sa.String(8), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(64), nullable=False),
        sa.Column("key_package_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.CheckConstraint("scope IN ('FILE','SHARE')", name="ck_digital_signatures_scope"),
        sa.CheckConstraint("payload_version=1", name="ck_digital_signatures_payload_version"),
        sa.CheckConstraint("signing_key_version>=1", name="ck_digital_signatures_key_version"),
        sa.CheckConstraint("(scope='FILE' AND file_share_id IS NULL) OR (scope='SHARE' AND file_share_id IS NOT NULL)", name="ck_digital_signatures_scope_shape"),
        sa.CheckConstraint("length(ciphertext_sha256)=64 AND length(key_package_sha256)=64", name="ck_digital_signatures_digest_length"),
        sa.CheckConstraint(
            "(algorithm='ML-DSA-44' AND profile_id='QS-SIG-MLDSA44-V1' AND length(signature)=2420) OR "
            "(algorithm='ML-DSA-65' AND profile_id='QS-SIG-MLDSA65-V1' AND length(signature)=3309) OR "
            "(algorithm='ML-DSA-87' AND profile_id='QS-SIG-MLDSA87-V1' AND length(signature)=4627)",
            name="ck_digital_signatures_algorithm_profile_length"),
    )
    op.create_index("uq_digital_signatures_file_scope", "digital_signatures", ["file_id"], unique=True,
                    postgresql_where=sa.text("scope = 'FILE'"))
    op.create_index("uq_digital_signatures_share", "digital_signatures", ["file_share_id"], unique=True,
                    postgresql_where=sa.text("file_share_id IS NOT NULL"))


def downgrade() -> None:
    op.execute("DO $$ BEGIN IF EXISTS (SELECT 1 FROM digital_signatures) "
               "OR EXISTS (SELECT 1 FROM user_crypto_keys WHERE key_purpose='SIGNATURE') "
               "OR EXISTS (SELECT 1 FROM files WHERE signature_required) "
               "OR EXISTS (SELECT 1 FROM file_shares WHERE signature_required) "
               "THEN RAISE EXCEPTION 'Signed records must be preserved before downgrade'; END IF; END $$")
    op.drop_index("uq_digital_signatures_share", table_name="digital_signatures")
    op.drop_index("uq_digital_signatures_file_scope", table_name="digital_signatures")
    op.drop_table("digital_signatures")
    op.drop_column("file_shares", "signature_required")
    op.drop_column("files", "signature_required")
    op.drop_constraint("ck_user_crypto_key_purpose_algorithm", "user_crypto_keys", type_="check")
    op.drop_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys", type_="check")
    op.drop_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys", type_="check")
    op.create_check_constraint("ck_user_crypto_supported_algorithm", "user_crypto_keys",
        "algorithm IN ('ML-KEM-512','ML-KEM-768','ML-KEM-1024','X25519')")
    op.create_check_constraint("ck_user_crypto_mlkem_lengths", "user_crypto_keys",
        "(algorithm!='ML-KEM-512' OR (length(public_key)=800 AND length(encrypted_private_key)=1648)) AND "
        "(algorithm!='ML-KEM-768' OR (length(public_key)=1184 AND length(encrypted_private_key)=80)) AND "
        "(algorithm!='ML-KEM-1024' OR (length(public_key)=1568 AND length(encrypted_private_key)=80)) AND "
        "(algorithm!='X25519' OR (length(public_key)=32 AND length(encrypted_private_key)=48))")
    op.drop_column("user_crypto_keys", "key_purpose")
