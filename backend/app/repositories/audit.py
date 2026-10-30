"""Append-only audit operations; no cryptographic or file contents are recorded."""

from uuid import UUID

from sqlalchemy import exists, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


class AuditRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record(self, event_type: str, *, actor_user_id: UUID, file_id: UUID,
               share_id: UUID | None = None, recipient_id: UUID | None = None,
               previous_status: str | None = None, new_status: str | None = None,
               reason: str | None = None) -> AuditLog:
        event = AuditLog(event_type=event_type, actor_user_id=actor_user_id,
                         file_id=file_id, share_id=share_id, recipient_id=recipient_id,
                         previous_status=previous_status, new_status=new_status,
                         reason=reason)
        self.session.add(event)
        return event

    def was_revoked(self, share_id: UUID) -> bool:
        statement = select(exists().where(
            AuditLog.share_id == share_id,
            AuditLog.event_type == "SHARE_REVOKED",
        ))
        return bool(self.session.scalar(statement))
