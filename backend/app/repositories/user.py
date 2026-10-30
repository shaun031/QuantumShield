"""User persistence operations."""

from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def get_by_id(self, user_id: UUID) -> User | None:
        return self.session.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        statement = select(User).where(User.email == email)
        return self.session.scalar(statement)

    def add(self, user: User) -> None:
        self.session.add(user)

    def search_active(
        self,
        query: str,
        *,
        exclude_user_id: UUID,
        limit: int,
    ) -> list[User]:
        normalized = query.strip().lower()
        statement = (
            select(User)
            .where(
                User.is_active.is_(True),
                User.id != exclude_user_id,
                or_(
                    func.lower(User.name).contains(normalized, autoescape=True),
                    func.lower(User.email).contains(normalized, autoescape=True),
                ),
            )
            .order_by(func.lower(User.name), User.id)
            .limit(limit)
        )
        return list(self.session.scalars(statement))

