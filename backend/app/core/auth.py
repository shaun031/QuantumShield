"""JWT access-token creation and strict decoding."""

from datetime import datetime, timedelta, timezone

import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import settings
from app.schemas.auth import TokenPayload


class InvalidAccessTokenError(ValueError):
    """Raised when a token is malformed, expired, or fails validation."""


def create_access_token(
    subject: str,
    *,
    expires_delta: timedelta | None = None,
) -> str:
    now = datetime.now(timezone.utc)
    expires_at = now + (
        expires_delta
        if expires_delta is not None
        else timedelta(minutes=settings.access_token_expire_minutes)
    )
    payload = {
        "sub": subject,
        "iat": now,
        "exp": expires_at,
        "type": "access",
    }
    return jwt.encode(
        payload,
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def decode_access_token(token: str) -> TokenPayload:
    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[settings.jwt_algorithm],
            options={"require": ["sub", "iat", "exp", "type"]},
        )
        token_payload = TokenPayload.model_validate(payload)
        if token_payload.type != "access":
            raise InvalidAccessTokenError("Unexpected token type")
        return token_payload
    except (InvalidTokenError, ValueError) as exc:
        raise InvalidAccessTokenError("Invalid access token") from exc

