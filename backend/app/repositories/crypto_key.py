"""Persistence operations for versioned user cryptographic keys."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.user_crypto_key import UserCryptoKey


class CryptoKeyRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, key: UserCryptoKey) -> None:
        self.session.add(key)

    def get_active(self, user_id: UUID, algorithm: str) -> UserCryptoKey | None:
        statement = select(UserCryptoKey).where(
            UserCryptoKey.user_id == user_id,
            UserCryptoKey.algorithm == algorithm,
            UserCryptoKey.is_active.is_(True),
            UserCryptoKey.revoked_at.is_(None),
        )
        return self.session.scalar(statement)

    def get_for_user(self, user_id: UUID, key_id: UUID) -> UserCryptoKey | None:
        statement = select(UserCryptoKey).where(
            UserCryptoKey.id == key_id,
            UserCryptoKey.user_id == user_id,
        )
        return self.session.scalar(statement)

    def list_active(self, user_id: UUID) -> list[UserCryptoKey]:
        statement = select(UserCryptoKey).where(
            UserCryptoKey.user_id == user_id,
            UserCryptoKey.is_active.is_(True),
            UserCryptoKey.revoked_at.is_(None),
        )
        return list(self.session.scalars(statement))

    def next_version(self, user_id: UUID, algorithm: str) -> int:
        statement = select(func.max(UserCryptoKey.key_version)).where(
            UserCryptoKey.user_id == user_id,
            UserCryptoKey.algorithm == algorithm,
        )
        return (self.session.scalar(statement) or 0) + 1
