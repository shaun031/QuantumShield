"""Phase 2 authentication and security behavior tests."""

from datetime import timedelta
from uuid import UUID

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.auth import create_access_token
from app.core.config import settings
from app.models.user import User


REGISTER_PAYLOAD = {
    "name": "Alice Example",
    "email": "Alice@Example.com",
    "password": "StrongPassword123!",
}


def register_user(client: TestClient) -> dict[str, object]:
    response = client.post("/api/auth/register", json=REGISTER_PAYLOAD)
    assert response.status_code == 201
    return response.json()


def login_user(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/api/auth/login",
        json={
            "email": "alice@example.com",
            "password": REGISTER_PAYLOAD["password"],
        },
    )
    assert response.status_code == 200
    return response.json()


def test_registration_normalizes_email_and_never_returns_hash(
    client: TestClient,
    db_session: Session,
) -> None:
    body = register_user(client)

    assert body["name"] == "Alice Example"
    assert body["email"] == "alice@example.com"
    assert body["is_active"] is True
    assert "password" not in body
    assert "password_hash" not in body

    user = db_session.scalar(select(User).where(User.email == "alice@example.com"))
    assert user is not None
    assert user.password_hash.startswith("$argon2id$")
    assert user.password_hash != REGISTER_PAYLOAD["password"]
    assert str(REGISTER_PAYLOAD["password"]) not in user.password_hash


def test_duplicate_normalized_email_is_rejected(client: TestClient) -> None:
    register_user(client)
    duplicate = {
        **REGISTER_PAYLOAD,
        "email": "ALICE@example.COM",
    }

    response = client.post("/api/auth/register", json=duplicate)

    assert response.status_code == 409
    assert response.json() == {
        "detail": "An account with this email already exists"
    }


def test_password_length_is_bounded(client: TestClient) -> None:
    too_short = client.post(
        "/api/auth/register",
        json={**REGISTER_PAYLOAD, "password": "short"},
    )
    too_long = client.post(
        "/api/auth/register",
        json={**REGISTER_PAYLOAD, "password": "x" * 129},
    )

    assert too_short.status_code == 422
    assert too_long.status_code == 422


@pytest.mark.parametrize("expiry_minutes", [30, 60])
def test_login_returns_expiring_minimal_access_token(
    client: TestClient, monkeypatch, expiry_minutes: int
) -> None:
    monkeypatch.setattr(settings, "access_token_expire_minutes", expiry_minutes)
    register_user(client)

    token_response = login_user(client)

    assert token_response["token_type"] == "bearer"
    assert token_response["expires_in"] == expiry_minutes * 60
    payload = jwt.decode(
        token_response["access_token"],
        settings.secret_key.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        options={"require": ["sub", "iat", "exp", "type"]},
    )
    assert set(payload) == {"sub", "iat", "exp", "type"}
    assert payload["type"] == "access"
    assert payload["exp"] - payload["iat"] == expiry_minutes * 60
    UUID(payload["sub"])
    assert "password" not in payload
    assert "password_hash" not in payload


def test_wrong_and_unknown_credentials_share_one_failure(client: TestClient) -> None:
    register_user(client)
    wrong_password = client.post(
        "/api/auth/login",
        json={"email": "alice@example.com", "password": "WrongPassword123!"},
    )
    unknown_email = client.post(
        "/api/auth/login",
        json={"email": "nobody@example.com", "password": "WrongPassword123!"},
    )

    assert wrong_password.status_code == 401
    assert unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json() == {
        "detail": "Invalid email or password"
    }


def test_current_user_requires_bearer_token(client: TestClient) -> None:
    missing = client.get("/api/users/me")
    wrong_scheme = client.get(
        "/api/users/me",
        headers={"Authorization": "Basic not-a-bearer-token"},
    )
    malformed = client.get(
        "/api/users/me",
        headers={"Authorization": "Bearer malformed.token"},
    )

    assert missing.status_code == 401
    assert wrong_scheme.status_code == 401
    assert malformed.status_code == 401
    assert "password_hash" not in malformed.text


def test_current_user_returns_safe_profile(client: TestClient) -> None:
    registered = register_user(client)
    token = login_user(client)["access_token"]

    response = client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.json()["id"] == registered["id"]
    assert response.json()["email"] == "alice@example.com"
    assert "password_hash" not in response.json()


def test_expired_token_is_rejected(client: TestClient) -> None:
    registered = register_user(client)
    expired_token = create_access_token(
        registered["id"],
        expires_delta=timedelta(seconds=-1),
    )

    response = client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )

    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials"}


def test_inactive_user_cannot_login_or_use_existing_token(
    client: TestClient,
    db_session: Session,
) -> None:
    registered = register_user(client)
    active_token = login_user(client)["access_token"]
    user = db_session.get(User, UUID(registered["id"]))
    assert user is not None
    user.is_active = False
    db_session.commit()

    login_response = client.post(
        "/api/auth/login",
        json={
            "email": "alice@example.com",
            "password": REGISTER_PAYLOAD["password"],
        },
    )
    profile_response = client.get(
        "/api/users/me",
        headers={"Authorization": f"Bearer {active_token}"},
    )

    assert login_response.status_code == 401
    assert profile_response.status_code == 403
    assert profile_response.json() == {"detail": "Inactive user account"}
