"""Server-managed, purpose-separated cryptographic user keys."""

import base64
from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.crypto_metadata import CryptoMetadata
    from app.models.share_crypto_metadata import ShareCryptoMetadata
    from app.models.user import User


class UserCryptoKey(Base):
    __tablename__ = "user_crypto_keys"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "algorithm",
            "key_version",
            name="uq_user_crypto_keys_user_algorithm_version",
        ),
        CheckConstraint("key_version >= 1", name="ck_user_crypto_key_version_positive"),
        CheckConstraint(
            "private_key_protection_version >= 1",
            name="ck_user_crypto_protection_version_positive",
        ),
        CheckConstraint(
            "length(public_key) > 0",
            name="ck_user_crypto_public_key_present",
        ),
        CheckConstraint(
            "length(encrypted_private_key) > 16",
            name="ck_user_crypto_encrypted_private_key_present",
        ),
        CheckConstraint(
            "length(private_key_nonce) = 12",
            name="ck_user_crypto_private_nonce_length",
        ),
        CheckConstraint(
            "algorithm IN ('ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'X25519', "
            "'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87')",
            name="ck_user_crypto_supported_algorithm",
        ),
        CheckConstraint(
            "(key_purpose = 'KEM' AND algorithm IN ('ML-KEM-512','ML-KEM-768','ML-KEM-1024')) OR "
            "(key_purpose = 'KEY_AGREEMENT' AND algorithm = 'X25519') OR "
            "(key_purpose = 'SIGNATURE' AND algorithm IN ('ML-DSA-44','ML-DSA-65','ML-DSA-87'))",
            name="ck_user_crypto_key_purpose_algorithm",
        ),
        CheckConstraint(
            "(algorithm != 'ML-KEM-512' OR "
            "(length(public_key) = 800 AND length(encrypted_private_key) = 1648)) "
            "AND (algorithm != 'ML-KEM-768' OR "
            "(length(public_key) = 1184 AND length(encrypted_private_key) = 80)) "
            "AND (algorithm != 'ML-KEM-1024' OR "
            "(length(public_key) = 1568 AND length(encrypted_private_key) = 80)) "
            "AND (algorithm != 'X25519' OR "
            "(length(public_key) = 32 AND length(encrypted_private_key) = 48)) "
            "AND (algorithm != 'ML-DSA-44' OR (length(public_key) = 1312 AND length(encrypted_private_key) = 48)) "
            "AND (algorithm != 'ML-DSA-65' OR (length(public_key) = 1952 AND length(encrypted_private_key) = 48)) "
            "AND (algorithm != 'ML-DSA-87' OR (length(public_key) = 2592 AND length(encrypted_private_key) = 48))",
            name="ck_user_crypto_mlkem_lengths",
        ),
        Index("ix_user_crypto_keys_user_active", "user_id", "algorithm", "is_active"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    key_purpose: Mapped[str] = mapped_column(String(16), nullable=False, default="KEM", server_default="KEM")
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    private_key_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    private_key_protection_algorithm: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )
    private_key_protection_version: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
    )
    key_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship(back_populates="crypto_keys")
    file_crypto_records: Mapped[list["CryptoMetadata"]] = relationship(
        back_populates="recipient_key", foreign_keys="CryptoMetadata.recipient_key_id"
    )
    share_crypto_records: Mapped[list["ShareCryptoMetadata"]] = relationship(
        back_populates="recipient_key", foreign_keys="ShareCryptoMetadata.recipient_key_id"
    )

    @property
    def public_key_base64(self) -> str:
        return base64.b64encode(self.public_key).decode("ascii")
