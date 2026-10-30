"""Secret-free, append-oriented application security events."""

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, String, Uuid, func, text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        CheckConstraint("event_type IN ('SHARE_CREATED','SHARE_REVOKED',"
                        "'SHARE_DOWNLOAD_DENIED_REVOKED','FILE_DELETED')",
                        name="ck_audit_logs_event_type"),
        CheckConstraint("previous_status IS NULL OR previous_status IN ('ACTIVE','REVOKED')",
                        name="ck_audit_logs_previous_status"),
        CheckConstraint("new_status IS NULL OR new_status IN ('ACTIVE','REVOKED')",
                        name="ck_audit_logs_new_status"),
        Index("ix_audit_logs_share_created", "share_id", "created_at"),
        Index("ix_audit_logs_file_created", "file_id", "created_at"),
        Index("uq_audit_logs_share_revoked", "share_id", unique=True,
              postgresql_where=text("event_type = 'SHARE_REVOKED'"),
              sqlite_where=text("event_type = 'SHARE_REVOKED'")),
    )

    id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid4)
    event_type: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    # These IDs deliberately outlive file/share deletion and have no FK cascade.
    file_id: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    share_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    recipient_id: Mapped[UUID | None] = mapped_column(Uuid(as_uuid=True))
    previous_status: Mapped[str | None] = mapped_column(String(16))
    new_status: Mapped[str | None] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False,
                                                 server_default=func.now())
