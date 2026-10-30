"""Versioned cryptographic metadata for encrypted file objects."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    LargeBinary,
    SmallInteger,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.file import File
    from app.models.user_crypto_key import UserCryptoKey


class CryptoMetadata(Base):
    __tablename__ = "file_crypto_metadata"
    __table_args__ = (
        CheckConstraint("crypto_version >= 1", name="ck_file_crypto_version_positive"),
        CheckConstraint("aad_version >= 1", name="ck_file_crypto_aad_version_positive"),
        CheckConstraint(
            "length(content_nonce) = 12",
            name="ck_file_crypto_content_nonce_length",
        ),
        CheckConstraint(
            "length(wrapped_file_key) = 48",
            name="ck_file_crypto_wrapped_key_length",
        ),
        CheckConstraint(
            "length(key_wrap_nonce) = 12",
            name="ck_file_crypto_wrap_nonce_length",
        ),
        CheckConstraint(
            "recipient_key_version IS NULL OR recipient_key_version >= 1",
            name="ck_file_crypto_recipient_key_version_positive",
        ),
        CheckConstraint(
            "crypto_version NOT IN (2, 3, 4) OR "
            "(kem_algorithm IS NOT NULL AND kem_ciphertext IS NOT NULL "
            "AND kdf_algorithm IS NOT NULL AND length(kdf_salt) = 32 "
            "AND recipient_key_id IS NOT NULL "
            "AND recipient_key_version IS NOT NULL "
            "AND security_level IS NOT NULL)",
            name="ck_file_crypto_kem_metadata_present",
        ),
        CheckConstraint(
            "kem_algorithm IS NULL OR "
            "(kem_algorithm = 'ML-KEM-512' AND length(kem_ciphertext) = 768) OR "
            "(kem_algorithm = 'ML-KEM-768' AND length(kem_ciphertext) = 1088) OR "
            "(kem_algorithm = 'ML-KEM-1024' AND length(kem_ciphertext) = 1568)",
            name="ck_file_crypto_mlkem_ciphertext_length",
        ),
        CheckConstraint(
            "crypto_version NOT IN (2, 3, 4) OR (security_level IS NOT NULL AND ("
            "(security_level = 'LOW' AND kem_algorithm = 'ML-KEM-512') OR "
            "(security_level = 'STANDARD' AND kem_algorithm = 'ML-KEM-768') OR "
            "(security_level = 'HIGH' AND kem_algorithm = 'ML-KEM-1024')))",
            name="ck_file_crypto_security_algorithm_match",
        ),
        CheckConstraint(
            "crypto_version = 1 OR (crypto_suite_id IS NOT NULL "
            "AND crypto_suite_version = 1)",
            name="ck_file_crypto_suite_metadata_present",
        ),
        CheckConstraint(
            "crypto_suite_id IS NULL OR "
            "(crypto_suite_id = 'QS-PQ-512-V1' AND security_level = 'LOW' "
            "AND kem_algorithm = 'ML-KEM-512' AND content_algorithm = 'AES-256-GCM' "
            "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-PQ-768-V1' AND security_level = 'STANDARD' "
            "AND kem_algorithm = 'ML-KEM-768' AND content_algorithm = 'AES-256-GCM' "
            "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-PQ-1024-V1' AND security_level = 'HIGH' "
            "AND kem_algorithm = 'ML-KEM-1024' AND content_algorithm = 'AES-256-GCM' "
            "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-HYBRID-512-V1' AND security_level = 'LOW' "
            "AND kem_algorithm = 'ML-KEM-512' AND content_algorithm = 'AES-256-GCM' "
            "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-HYBRID-768-V1' AND security_level = 'STANDARD' "
            "AND kem_algorithm = 'ML-KEM-768' AND content_algorithm = 'AES-256-GCM' "
            "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM') OR "
            "(crypto_suite_id = 'QS-HYBRID-1024-V1' AND security_level = 'HIGH' "
            "AND kem_algorithm = 'ML-KEM-1024' AND content_algorithm = 'AES-256-GCM' "
            "AND kdf_algorithm = 'HKDF-SHA256' AND key_wrap_algorithm = 'KEK-AES-256-GCM')",
            name="ck_file_crypto_suite_algorithm_match",
        ),
        CheckConstraint("security_architecture IN ('PQ_ONLY', 'HYBRID')", name="ck_file_crypto_architecture"),
        CheckConstraint(
            "(crypto_version = 4 AND aad_version = 4 AND security_architecture = 'HYBRID' AND classical_algorithm = 'X25519' "
            "AND length(ephemeral_public_key) = 32 AND recipient_classical_key_id IS NOT NULL "
            "AND recipient_classical_key_version >= 1 AND combiner_version = 1 "
            "AND crypto_suite_id LIKE 'QS-HYBRID-%') OR "
            "(crypto_version != 4 AND security_architecture = 'PQ_ONLY' AND classical_algorithm IS NULL "
            "AND ephemeral_public_key IS NULL AND recipient_classical_key_id IS NULL "
            "AND recipient_classical_key_version IS NULL AND combiner_version IS NULL "
            "AND (crypto_suite_id IS NULL OR crypto_suite_id LIKE 'QS-PQ-%'))",
            name="ck_file_crypto_hybrid_metadata",
        ),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    file_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    content_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    content_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    wrapped_file_key: Mapped[bytes] = mapped_column(LargeBinary(48), nullable=False)
    key_wrap_algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    key_wrap_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    kem_algorithm: Mapped[str | None] = mapped_column(String(32))
    kem_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    kdf_algorithm: Mapped[str | None] = mapped_column(String(32))
    kdf_salt: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    recipient_key_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("user_crypto_keys.id", ondelete="RESTRICT"),
    )
    recipient_key_version: Mapped[int | None] = mapped_column(SmallInteger)
    security_level: Mapped[str | None] = mapped_column(String(16))
    crypto_suite_id: Mapped[str | None] = mapped_column(String(32))
    crypto_suite_version: Mapped[int | None] = mapped_column(SmallInteger)
    security_architecture: Mapped[str] = mapped_column(String(16), nullable=False, default="PQ_ONLY", server_default="PQ_ONLY")
    classical_algorithm: Mapped[str | None] = mapped_column(String(32))
    ephemeral_public_key: Mapped[bytes | None] = mapped_column(LargeBinary(32))
    recipient_classical_key_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("user_crypto_keys.id", ondelete="RESTRICT"))
    recipient_classical_key_version: Mapped[int | None] = mapped_column(SmallInteger)
    combiner_version: Mapped[int | None] = mapped_column(SmallInteger)
    crypto_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    aad_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    file: Mapped["File"] = relationship(back_populates="crypto_metadata")
    recipient_key: Mapped["UserCryptoKey | None"] = relationship(
        back_populates="file_crypto_records", foreign_keys=[recipient_key_id]
    )
    recipient_classical_key: Mapped["UserCryptoKey | None"] = relationship(foreign_keys=[recipient_classical_key_id])
