"""Recipient-specific ML-KEM envelope for an existing encrypted file key."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, LargeBinary, SmallInteger, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.file_share import FileShare
    from app.models.user_crypto_key import UserCryptoKey


class ShareCryptoMetadata(Base):
    __tablename__ = "share_crypto_metadata"
    __table_args__ = (
        CheckConstraint("crypto_version >= 1", name="ck_share_crypto_version_positive"),
        CheckConstraint("aad_version >= 1", name="ck_share_crypto_aad_version_positive"),
        CheckConstraint(
            "recipient_key_version >= 1",
            name="ck_share_crypto_recipient_key_version_positive",
        ),
        CheckConstraint("length(kdf_salt) = 32", name="ck_share_crypto_kdf_salt_length"),
        CheckConstraint(
            "length(wrapped_file_key) = 48",
            name="ck_share_crypto_wrapped_key_length",
        ),
        CheckConstraint(
            "length(key_wrap_nonce) = 12",
            name="ck_share_crypto_wrap_nonce_length",
        ),
        CheckConstraint(
            "(kem_algorithm = 'ML-KEM-512' AND length(kem_ciphertext) = 768) OR "
            "(kem_algorithm = 'ML-KEM-768' AND length(kem_ciphertext) = 1088) OR "
            "(kem_algorithm = 'ML-KEM-1024' AND length(kem_ciphertext) = 1568)",
            name="ck_share_crypto_mlkem_ciphertext_length",
        ),
        CheckConstraint(
            "(security_level = 'LOW' AND kem_algorithm = 'ML-KEM-512') OR "
            "(security_level = 'STANDARD' AND kem_algorithm = 'ML-KEM-768') OR "
            "(security_level = 'HIGH' AND kem_algorithm = 'ML-KEM-1024')",
            name="ck_share_crypto_security_algorithm_match",
        ),
        CheckConstraint(
            "crypto_suite_version = 1",
            name="ck_share_crypto_suite_version",
        ),
        CheckConstraint(
            "(crypto_suite_id = 'QS-PQ-512-V1' AND security_level = 'LOW' "
            "AND kem_algorithm = 'ML-KEM-512' AND kdf_algorithm = 'HKDF-SHA256' "
            "AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-PQ-768-V1' AND security_level = 'STANDARD' "
            "AND kem_algorithm = 'ML-KEM-768' AND kdf_algorithm = 'HKDF-SHA256' "
            "AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-PQ-1024-V1' AND security_level = 'HIGH' "
            "AND kem_algorithm = 'ML-KEM-1024' AND kdf_algorithm = 'HKDF-SHA256' "
            "AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-HYBRID-512-V1' AND security_level = 'LOW' "
            "AND kem_algorithm = 'ML-KEM-512' AND kdf_algorithm = 'HKDF-SHA256' "
            "AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-HYBRID-768-V1' AND security_level = 'STANDARD' "
            "AND kem_algorithm = 'ML-KEM-768' AND kdf_algorithm = 'HKDF-SHA256' "
            "AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-HYBRID-1024-V1' AND security_level = 'HIGH' "
            "AND kem_algorithm = 'ML-KEM-1024' AND kdf_algorithm = 'HKDF-SHA256' "
            "AND key_wrap_algorithm = 'KEK-AES-256-GCM')",
            name="ck_share_crypto_suite_algorithm_match",
        ),
        CheckConstraint("security_architecture IN ('PQ_ONLY', 'HYBRID')", name="ck_share_crypto_architecture"),
        CheckConstraint(
            "(crypto_version = 3 AND aad_version = 3 AND security_architecture = 'HYBRID' AND classical_algorithm = 'X25519' "
            "AND length(ephemeral_public_key) = 32 AND recipient_classical_key_id IS NOT NULL "
            "AND recipient_classical_key_version >= 1 AND combiner_version = 1 "
            "AND crypto_suite_id LIKE 'QS-HYBRID-%') OR "
            "(crypto_version != 3 AND security_architecture = 'PQ_ONLY' AND classical_algorithm IS NULL "
            "AND ephemeral_public_key IS NULL AND recipient_classical_key_id IS NULL "
            "AND recipient_classical_key_version IS NULL AND combiner_version IS NULL "
            "AND crypto_suite_id LIKE 'QS-PQ-%')",
            name="ck_share_crypto_hybrid_metadata",
        ),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    file_share_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("file_shares.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, server_default="true")
    recipient_key_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("user_crypto_keys.id", ondelete="RESTRICT"),
        nullable=False,
    )
    recipient_key_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    security_level: Mapped[str] = mapped_column(String(16), nullable=False)
    crypto_suite_id: Mapped[str] = mapped_column(String(32), nullable=False)
    crypto_suite_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    security_architecture: Mapped[str] = mapped_column(String(16), nullable=False, default="PQ_ONLY", server_default="PQ_ONLY")
    classical_algorithm: Mapped[str | None] = mapped_column(String(32))
    ephemeral_public_key: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    recipient_classical_key_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("user_crypto_keys.id", ondelete="RESTRICT"))
    recipient_classical_key_version: Mapped[int | None] = mapped_column(SmallInteger)
    combiner_version: Mapped[int | None] = mapped_column(SmallInteger)
    kem_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    kem_ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    kdf_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    key_wrap_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    wrapped_file_key: Mapped[bytes] = mapped_column(LargeBinary(48), nullable=False)
    key_wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    crypto_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    aad_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    share: Mapped["FileShare"] = relationship(back_populates="crypto_access")
    recipient_key: Mapped["UserCryptoKey"] = relationship(
        back_populates="share_crypto_records", foreign_keys=[recipient_key_id]
    )
    recipient_classical_key: Mapped["UserCryptoKey | None"] = relationship(foreign_keys=[recipient_classical_key_id])
