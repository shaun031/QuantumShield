"""Authorized user-to-user access to one encrypted file."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Index, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.digital_signature import DigitalSignature
    from app.models.file import File
    from app.models.share_crypto_metadata import ShareCryptoMetadata
    from app.models.user import User


class FileShare(Base):
    __tablename__ = "file_shares"
    __table_args__ = (
        Index("uq_file_shares_file_recipient_active", "file_id", "recipient_id", unique=True,
              postgresql_where=text("status = 'ACTIVE'"), sqlite_where=text("status = 'ACTIVE'")),
        CheckConstraint("sender_id != recipient_id", name="ck_file_shares_distinct_users"),
        CheckConstraint("permission = 'READ'", name="ck_file_shares_read_only"),
        CheckConstraint("status IN ('ACTIVE', 'REVOKED')", name="ck_file_shares_status"),
        CheckConstraint("(status = 'ACTIVE' AND revoked_at IS NULL AND revoked_by_user_id IS NULL) OR "
                        "(status = 'REVOKED' AND revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL)",
                        name="ck_file_shares_revocation_state"),
        CheckConstraint("revoke_reason IS NULL OR length(revoke_reason) <= 255",
                        name="ck_file_shares_revoke_reason_length"),
        Index("ix_file_shares_recipient_created", "recipient_id", "created_at"),
        Index("ix_file_shares_sender_created", "sender_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    file_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    sender_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    recipient_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    permission: Mapped[str] = mapped_column(
        String(16), nullable=False, default="READ", server_default="READ"
    )
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ACTIVE", server_default="ACTIVE"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by_user_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT", name="fk_file_shares_revoked_by")
    )
    revoke_reason: Mapped[str | None] = mapped_column(String(255))
    signature_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    file: Mapped["File"] = relationship(back_populates="shares")
    sender: Mapped["User"] = relationship(
        back_populates="sent_shares", foreign_keys=[sender_id]
    )
    recipient: Mapped["User"] = relationship(
        back_populates="received_shares", foreign_keys=[recipient_id]
    )
    crypto_access: Mapped["ShareCryptoMetadata | None"] = relationship(
        back_populates="share",
        cascade="all, delete-orphan",
        single_parent=True,
        uselist=False,
    )
    signature: Mapped["DigitalSignature | None"] = relationship(
        back_populates="share", cascade="all, delete-orphan", single_parent=True, uselist=False
    )

    @property
    def kem_algorithm(self) -> str:
        return self.crypto_access.kem_algorithm if self.crypto_access is not None else "UNAVAILABLE"

    @property
    def security_level(self) -> str:
        return self.crypto_access.security_level if self.crypto_access is not None else "UNAVAILABLE"

    @property
    def crypto_suite_id(self) -> str:
        return self.crypto_access.crypto_suite_id if self.crypto_access is not None else "UNAVAILABLE"

    @property
    def security_architecture(self) -> str:
        return self.crypto_access.security_architecture if self.crypto_access is not None else "UNAVAILABLE"

    @property
    def classical_algorithm(self) -> str | None:
        return self.crypto_access.classical_algorithm if self.crypto_access is not None else None
