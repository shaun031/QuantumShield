"""Database access for owner-scoped file metadata."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.file import File


class FileRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, file_record: File) -> File:
        self.session.add(file_record)
        return file_record

    def get_for_owner(self, owner_id: UUID, file_id: UUID) -> File | None:
        statement = (
            select(File)
            .options(selectinload(File.crypto_metadata))
            .where(
                File.id == file_id,
                File.owner_id == owner_id,
            )
        )
        return self.session.scalar(statement)

    def list_for_owner(
        self,
        owner_id: UUID,
        *,
        limit: int,
        offset: int,
    ) -> list[File]:
        statement = (
            select(File)
            .options(selectinload(File.crypto_metadata))
            .where(File.owner_id == owner_id)
            .order_by(File.created_at.desc(), File.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self.session.scalars(statement))

    def delete(self, file_record: File) -> None:
        self.session.delete(file_record)
