"""Registration and credential-authentication use cases."""

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.auth import create_access_token
from app.core.config import settings
from app.core.passwords import (
    hash_password,
    perform_dummy_password_verification,
    verify_password,
)
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.auth import TokenResponse, UserCreate
from app.services.crypto_keys import CryptoKeyService


class DuplicateEmailError(ValueError):
    """Raised when registration conflicts with an existing normalized email."""


def normalize_email(email: str) -> str:
    return email.strip().casefold()


class AuthService:
    def __init__(self, session: Session, crypto_keys: CryptoKeyService) -> None:
        self.session = session
        self.users = UserRepository(session)
        self.crypto_keys = crypto_keys

    def register_user(self, data: UserCreate) -> User:
        email = normalize_email(str(data.email))
        if self.users.get_by_email(email) is not None:
            raise DuplicateEmailError

        user = User(
            name=data.name,
            email=email,
            password_hash=hash_password(data.password),
        )
        self.users.add(user)

        try:
            self.session.flush()
            self.crypto_keys.ensure_keyset_for_user(user, commit=False)
            self.session.commit()
            self.session.refresh(user)
        except IntegrityError as exc:
            self.session.rollback()
            raise DuplicateEmailError from exc
        except SQLAlchemyError:
            self.session.rollback()
            raise
        except Exception:
            self.session.rollback()
            raise

        return user

    def authenticate_user(self, email: str, password: str) -> User | None:
        user = self.users.get_by_email(normalize_email(email))
        if user is None:
            perform_dummy_password_verification(password)
            return None

        password_is_valid = verify_password(password, user.password_hash)
        if not password_is_valid or not user.is_active:
            return None
        return user

    def create_login_token(self, user: User) -> TokenResponse:
        return TokenResponse(
            access_token=create_access_token(str(user.id)),
            expires_in=60 * settings.access_token_expire_minutes,
        )

