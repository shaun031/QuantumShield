"""Persistence operations for file shares and recipient envelopes."""

from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session, selectinload

from app.models.file_share import FileShare


class ShareRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    @staticmethod
    def _with_details():
        return (
            selectinload(FileShare.file),
            selectinload(FileShare.sender),
            selectinload(FileShare.recipient),
            selectinload(FileShare.crypto_access),
        )

    def add(self, share: FileShare) -> FileShare:
        self.session.add(share)
        return share

    def get_duplicate(self, file_id: UUID, recipient_id: UUID) -> FileShare | None:
        statement = select(FileShare).where(
            FileShare.file_id == file_id,
            FileShare.recipient_id == recipient_id,
            FileShare.status == "ACTIVE",
        )
        return self.session.scalar(statement)

    def get_visible(self, user_id: UUID, share_id: UUID) -> FileShare | None:
        statement = (
            select(FileShare)
            .options(*self._with_details())
            .where(
                FileShare.id == share_id,
                or_(
                    FileShare.sender_id == user_id,
                    FileShare.recipient_id == user_id,
                ),
            )
        )
        return self.session.scalar(statement)

    def get_for_recipient(self, recipient_id: UUID, share_id: UUID) -> FileShare | None:
        statement = (
            select(FileShare)
            .options(*self._with_details())
            .where(
                FileShare.id == share_id,
                FileShare.recipient_id == recipient_id,
            )
            .with_for_update(read=True, of=FileShare)
        )
        return self.session.scalar(statement)

    def list_received(self, recipient_id: UUID, *, limit: int, offset: int) -> list[FileShare]:
        statement = (
            select(FileShare)
            .options(*self._with_details())
            .where(
                FileShare.recipient_id == recipient_id,
            )
            .order_by(FileShare.created_at.desc(), FileShare.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(statement))

    def list_sent(self, sender_id: UUID, *, limit: int, offset: int) -> list[FileShare]:
        statement = (
            select(FileShare)
            .options(*self._with_details())
            .where(
                FileShare.sender_id == sender_id,
            )
            .order_by(FileShare.created_at.desc(), FileShare.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(statement))

    def get_for_sender(self, sender_id: UUID, share_id: UUID) -> FileShare | None:
        statement = (
            select(FileShare)
            .options(*self._with_details())
            .where(FileShare.id == share_id, FileShare.sender_id == sender_id)
        )
        return self.session.scalar(statement)
