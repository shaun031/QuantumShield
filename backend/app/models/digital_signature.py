"""Immutable FILE/SHARE signatures over canonical encrypted-package metadata."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, SmallInteger, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.file import File
    from app.models.file_share import FileShare
    from app.models.user_crypto_key import UserCryptoKey


class DigitalSignature(Base):
    __tablename__ = "digital_signatures"
    __table_args__ = (
        CheckConstraint("scope IN ('FILE','SHARE')", name="ck_digital_signatures_scope"),
        CheckConstraint("payload_version = 1", name="ck_digital_signatures_payload_version"),
        CheckConstraint("signing_key_version >= 1", name="ck_digital_signatures_key_version"),
        CheckConstraint("(scope = 'FILE' AND file_share_id IS NULL AND key_package_sha256 IS NOT NULL) OR "
                        "(scope = 'SHARE' AND file_share_id IS NOT NULL AND key_package_sha256 IS NOT NULL)",
                        name="ck_digital_signatures_scope_shape"),
        CheckConstraint("length(ciphertext_sha256) = 64 AND length(key_package_sha256) = 64",
                        name="ck_digital_signatures_digest_length"),
        CheckConstraint(
            "(algorithm = 'ML-DSA-44' AND profile_id = 'QS-SIG-MLDSA44-V1' AND length(signature) = 2420) OR "
            "(algorithm = 'ML-DSA-65' AND profile_id = 'QS-SIG-MLDSA65-V1' AND length(signature) = 3309) OR "
            "(algorithm = 'ML-DSA-87' AND profile_id = 'QS-SIG-MLDSA87-V1' AND length(signature) = 4627)",
            name="ck_digital_signatures_algorithm_profile_length",
        ),
        Index("uq_digital_signatures_file_scope", "file_id", unique=True,
              postgresql_where=text("scope = 'FILE'"), sqlite_where=text("scope = 'FILE'")),
        Index("uq_digital_signatures_share", "file_share_id", unique=True,
              postgresql_where=text("file_share_id IS NOT NULL"), sqlite_where=text("file_share_id IS NOT NULL")),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    file_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("files.id", ondelete="CASCADE"), nullable=False)
    file_share_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True), ForeignKey("file_shares.id", ondelete="CASCADE"))
    signer_user_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    signing_key_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), ForeignKey("user_crypto_keys.id", ondelete="RESTRICT"), nullable=False)
    signing_key_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False)
    profile_id: Mapped[str] = mapped_column(String(32), nullable=False)
    payload_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    scope: Mapped[str] = mapped_column(String(8), nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    key_package_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())

    file: Mapped["File"] = relationship(back_populates="signatures")
    share: Mapped["FileShare | None"] = relationship(back_populates="signature")
    signing_key: Mapped["UserCryptoKey"] = relationship()
