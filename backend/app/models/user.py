"""User persistence model for Phase 2 authentication."""

from datetime import datetime, timezone
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, String, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.file import File
    from app.models.file_share import FileShare
    from app.models.user_crypto_key import UserCryptoKey


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default="true",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
    )
    files: Mapped[list["File"]] = relationship(
        back_populates="owner",
        passive_deletes=True,
    )
    crypto_keys: Mapped[list["UserCryptoKey"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    sent_shares: Mapped[list["FileShare"]] = relationship(
        back_populates="sender",
        foreign_keys="FileShare.sender_id",
        passive_deletes=True,
    )
    received_shares: Mapped[list["FileShare"]] = relationship(
        back_populates="recipient",
        foreign_keys="FileShare.recipient_id",
        passive_deletes=True,
    )

