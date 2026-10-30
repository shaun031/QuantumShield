"""User ML-KEM provisioning, storage, and public API tests."""

import base64
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.dependencies import get_crypto_key_service
from app.main import app as application
from app.models.user import User
from app.models.user_crypto_key import UserCryptoKey


def register_and_login(client: TestClient, email: str) -> tuple[dict, dict[str, str]]:
    password = "StrongPassword123!"
    registered = client.post(
        "/api/auth/register",
        json={"name": "Crypto User", "email": email, "password": password},
    )
    assert registered.status_code == 201
    login = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login.status_code == 200
    return registered.json(), {
        "Authorization": f"Bearer {login.json()['access_token']}"
    }


def test_registration_creates_five_encrypted_key_records(
    client: TestClient,
    db_session: Session,
) -> None:
    registered, _ = register_and_login(client, "keys@example.com")
    records = list(db_session.scalars(
        select(UserCryptoKey).where(
            UserCryptoKey.user_id == UUID(registered["id"])
        ).order_by(UserCryptoKey.algorithm)
    ))

    assert {record.algorithm for record in records} == {
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519", "ML-DSA-65"
    }
    expected_lengths = {
        "ML-KEM-512": (800, 1648),
        "ML-KEM-768": (1184, 80),
        "ML-KEM-1024": (1568, 80),
        "X25519": (32, 48),
        "ML-DSA-65": (1952, 48),
    }
    for record in records:
        public_size, protected_size = expected_lengths[record.algorithm]
        assert record.key_version == 1 and record.is_active is True
        assert len(record.public_key) == public_size
        assert len(record.encrypted_private_key) == protected_size
        assert len(record.private_key_nonce) == 12
        assert b"T" * 32 not in record.encrypted_private_key


def test_authenticated_key_metadata_and_public_lookup_expose_no_secrets(
    client: TestClient,
) -> None:
    registered, headers = register_and_login(client, "lookup@example.com")

    mine = client.get("/api/crypto/keys/me", headers=headers)
    lookup = client.get(
        f"/api/crypto/public-key/{registered['id']}",
        headers=headers,
    )

    assert mine.status_code == lookup.status_code == 200
    assert len(mine.json()) == 5
    body = lookup.json()
    assert body["algorithm"] == "ML-KEM-768"
    assert body["public_key_available"] is True
    assert len(base64.b64decode(body["public_key_base64"])) == 1184
    for forbidden in (
        "private_key",
        "encrypted_private_key",
        "private_key_nonce",
        "master_key",
    ):
        assert forbidden not in mine.text
        assert forbidden not in body


def test_public_key_lookup_requires_authentication(client: TestClient) -> None:
    registered, _ = register_and_login(client, "private-lookup@example.com")
    response = client.get(f"/api/crypto/public-key/{registered['id']}")
    assert response.status_code == 401


def test_existing_user_provisioning_is_single_and_conflict_safe(
    client: TestClient,
    db_session: Session,
) -> None:
    registered, headers = register_and_login(client, "existing@example.com")
    keys = list(db_session.scalars(
        select(UserCryptoKey).where(
            UserCryptoKey.user_id == UUID(registered["id"])
        )
    ))
    for key in keys:
        if key.algorithm != "ML-KEM-768":
            db_session.delete(key)
    db_session.commit()

    created = client.post("/api/crypto/keys/ensure", headers=headers)
    duplicate = client.post("/api/crypto/keys/ensure", headers=headers)

    assert created.status_code == duplicate.status_code == 200
    assert len(created.json()) == len(duplicate.json()) == 5
    assert db_session.scalar(select(func.count()).select_from(UserCryptoKey)) == 5


def test_registration_rolls_back_when_crypto_provisioning_fails(
    client: TestClient,
    db_session: Session,
) -> None:
    class FailingCryptoKeyService:
        def ensure_keyset_for_user(self, user: User, *, commit: bool = True) -> None:
            del user, commit
            raise RuntimeError("provider unavailable")

    application.dependency_overrides[get_crypto_key_service] = (
        lambda: FailingCryptoKeyService()
    )

    response = client.post(
        "/api/auth/register",
        json={
            "name": "Rollback User",
            "email": "rollback@example.com",
            "password": "StrongPassword123!",
        },
    )

    assert response.status_code == 500
    assert db_session.scalar(select(func.count()).select_from(User)) == 0
    assert db_session.scalar(select(func.count()).select_from(UserCryptoKey)) == 0
