"""Owner file metadata with optional versioned encryption metadata."""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    JSON,
    String,
    Uuid,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.models.crypto_metadata import CryptoMetadata
    from app.models.digital_signature import DigitalSignature
    from app.models.file_share import FileShare
    from app.models.user import User


class File(Base):
    __tablename__ = "files"
    __table_args__ = (
        CheckConstraint("file_size >= 0", name="ck_files_file_size_nonnegative"),
        CheckConstraint(
            "security_selection_mode IS NULL OR security_selection_mode IN "
            "('MANUAL', 'RECOMMEND', 'AUTO')",
            name="ck_files_security_selection_mode",
        ),
        CheckConstraint(
            "sensitivity IS NULL OR sensitivity IN "
            "('PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'HIGHLY_CONFIDENTIAL')",
            name="ck_files_sensitivity",
        ),
        CheckConstraint(
            "document_category IS NULL OR document_category IN "
            "('GENERAL', 'ACADEMIC', 'PERSONAL', 'FINANCIAL', 'LEGAL', "
            "'MEDICAL', 'SOURCE_CODE', 'IDENTITY', 'CREDENTIALS', 'ARCHIVE', "
            "'OTHER')",
            name="ck_files_document_category",
        ),
        CheckConstraint(
            "recommended_security_level IS NULL OR recommended_security_level IN "
            "('LOW', 'STANDARD', 'HIGH')",
            name="ck_files_recommended_security_level",
        ),
        CheckConstraint(
            "security_selection_mode IS NULL OR "
            "(recommended_security_level IS NOT NULL AND policy_version IS NOT NULL "
            "AND decision_reasons IS NOT NULL AND policy_rules IS NOT NULL "
            "AND user_override IS NOT NULL)",
            name="ck_files_policy_decision_complete",
        ),
        Index("ix_files_owner_created_at", "owner_id", "created_at"),
    )

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid4,
    )
    owner_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_filename: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        unique=True,
    )
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False, unique=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        default="application/octet-stream",
        server_default="application/octet-stream",
    )
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    selection_mode: Mapped[str | None] = mapped_column(
        "security_selection_mode", String(16), nullable=True
    )
    sensitivity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    document_category: Mapped[str | None] = mapped_column(String(32), nullable=True)
    recommended_security_level: Mapped[str | None] = mapped_column(
        String(16), nullable=True
    )
    policy_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    decision_reasons: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    policy_rules: Mapped[list[dict[str, str]] | None] = mapped_column(JSON, nullable=True)
    user_override: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    signature_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default="false")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    owner: Mapped["User"] = relationship(back_populates="files")
    crypto_metadata: Mapped["CryptoMetadata | None"] = relationship(
        back_populates="file",
        cascade="all, delete-orphan",
        single_parent=True,
        uselist=False,
    )
    shares: Mapped[list["FileShare"]] = relationship(
        back_populates="file",
        cascade="all, delete-orphan",
    )
    signatures: Mapped[list["DigitalSignature"]] = relationship(
        back_populates="file", cascade="all, delete-orphan"
    )

    @property
    def is_encrypted(self) -> bool:
        return self.crypto_metadata is not None

    @property
    def encryption_algorithm(self) -> str | None:
        if self.crypto_metadata is None:
            return None
        return self.crypto_metadata.content_algorithm

    @property
    def post_quantum_protected(self) -> bool:
        return bool(
            self.crypto_metadata is not None
            and self.crypto_metadata.crypto_version in {2, 3, 4}
            and self.crypto_metadata.kem_algorithm is not None
        )

    @property
    def kem_algorithm(self) -> str | None:
        if self.crypto_metadata is None:
            return None
        return self.crypto_metadata.kem_algorithm

    @property
    def crypto_version(self) -> int | None:
        if self.crypto_metadata is None:
            return None
        return self.crypto_metadata.crypto_version

    @property
    def security_level(self) -> str | None:
        if self.crypto_metadata is None:
            return None
        return self.crypto_metadata.security_level

    @property
    def crypto_suite_id(self) -> str | None:
        if self.crypto_metadata is None:
            return None
        return self.crypto_metadata.crypto_suite_id

    @property
    def crypto_suite_version(self) -> int | None:
        if self.crypto_metadata is None:
            return None
        return self.crypto_metadata.crypto_suite_version

    @property
    def security_architecture(self) -> str | None:
        if self.crypto_metadata is None or self.crypto_metadata.crypto_version == 1:
            return None
        return self.crypto_metadata.security_architecture

    @property
    def classical_algorithm(self) -> str | None:
        return self.crypto_metadata.classical_algorithm if self.crypto_metadata else None
