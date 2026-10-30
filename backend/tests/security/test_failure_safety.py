"""Corrupt state, cleanup, safe errors, policy validation, and secret absence."""

import base64
import logging
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.session import get_db
from app.main import app
from app.models.digital_signature import DigitalSignature
from app.models.file import File
from app.models.user import User
from app.models.user_crypto_key import UserCryptoKey
from app.services.signatures import SignatureService
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login, upload


def assert_safe(response, expected: int) -> None:
    assert response.status_code == expected
    for forbidden in ("Traceback", "sqlalchemy", "SELECT ", "D:\\", "MASTER_KEY_BASE64", "private_key"):
        assert forbidden not in response.text


def test_missing_object_and_signature_fail_safely(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "missing-object@example.com")
    file_id = upload(client, headers, content=b"unavailable").json()["id"]
    record = db_session.get(File, UUID(file_id))
    assert record is not None
    path = storage_service.resolve_path(record.storage_path)
    ciphertext = path.read_bytes()
    path.unlink()
    assert_safe(client.get(f"/api/files/{file_id}/download", headers=headers), 404)
    path.write_bytes(ciphertext)
    signature = db_session.scalar(select(DigitalSignature).where(DigitalSignature.file_id == record.id))
    assert signature is not None
    db_session.delete(signature)
    db_session.commit()
    assert_safe(client.get(f"/api/files/{file_id}/download", headers=headers), 422)


def test_missing_crypto_metadata_is_not_treated_as_legacy(
    client: TestClient, db_session: Session,
) -> None:
    _, headers = register_and_login(client, "missing-crypto@example.com")
    file_id = upload(client, headers, content=b"signed encrypted file").json()["id"]
    record = db_session.get(File, UUID(file_id))
    assert record is not None and record.signature_required
    db_session.delete(record.crypto_metadata)
    db_session.commit()
    assert_safe(client.get(f"/api/files/{file_id}/download", headers=headers), 422)


def test_invalid_internal_storage_key_returns_safe_error(
    client: TestClient, db_session: Session,
) -> None:
    _, headers = register_and_login(client, "invalid-path@example.com")
    file_id = upload(client, headers, content=b"never read arbitrary paths").json()["id"]
    record = db_session.get(File, UUID(file_id))
    assert record is not None
    record.storage_path = "../../outside.enc"
    db_session.commit()
    assert_safe(client.get(f"/api/files/{file_id}/download", headers=headers), 422)


@pytest.mark.parametrize("selection_mode,security_level,sensitivity,category", [
    ("AUTO", "LOW", "HIGHLY_CONFIDENTIAL", "MEDICAL"),
    ("RECOMMEND", "LOW", "HIGHLY_CONFIDENTIAL", "MEDICAL"),
    ("UNKNOWN", "LOW", None, None),
    ("AUTO", None, "unknown", None),
    ("AUTO", None, None, "unknown"),
    ("auto", None, None, None),
])
def test_adaptive_downgrade_or_invalid_values_rejected(
    client: TestClient, selection_mode: str, security_level: str | None,
    sensitivity: str | None, category: str | None,
) -> None:
    _, headers = register_and_login(client, "policy-security@example.com")
    data = {"selection_mode": selection_mode}
    if security_level is not None:
        data["security_level"] = security_level
    if sensitivity is not None:
        data["sensitivity"] = sensitivity
    if category is not None:
        data["document_category"] = category
    response = client.post("/api/files/upload", headers=headers, data=data,
                           files={"file": ("record.txt", b"classification", "text/plain")})
    assert response.status_code == 422


def test_storage_write_failure_rolls_back_metadata(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers = register_and_login(client, "storage-failure@example.com")

    def fail_storage(data: bytes, object_key: str) -> None:
        raise PermissionError("simulated denied write")

    monkeypatch.setattr(storage_service, "save_bytes", fail_storage)
    assert_safe(upload(client, headers, content=b"no orphan"), 500)
    assert db_session.scalar(select(func.count()).select_from(File)) == 0
    assert not [path for path in storage_service.root.rglob("*") if path.is_file()]


def test_signature_failure_cleans_ciphertext_and_database(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers = register_and_login(client, "signature-failure@example.com")

    def fail_sign(*args, **kwargs):
        raise RuntimeError("simulated signing failure")

    monkeypatch.setattr(SignatureService, "sign_file", fail_sign)
    assert_safe(upload(client, headers, content=b"no orphan"), 500)
    assert db_session.scalar(select(func.count()).select_from(File)) == 0
    assert not [path for path in storage_service.root.rglob("*") if path.is_file()]


def test_commit_failure_cleans_ciphertext_and_database(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers = register_and_login(client, "commit-failure@example.com")
    app.dependency_overrides[get_db] = lambda: db_session

    def fail_commit() -> None:
        raise RuntimeError("simulated commit failure")

    monkeypatch.setattr(db_session, "commit", fail_commit)
    assert_safe(upload(client, headers, content=b"no orphan"), 500)
    assert db_session.scalar(select(func.count()).select_from(File)) == 0
    assert not [path for path in storage_service.root.rglob("*") if path.is_file()]


def test_password_private_keys_and_file_key_not_persisted_or_logged(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO)
    password = "StrongPassword123!"
    registered, headers = register_and_login(client, "secret-log@example.com")
    file_id = upload(client, headers, content=b"private test content").json()["id"]
    record = db_session.get(File, UUID(file_id))
    user = db_session.get(User, UUID(registered["id"]))
    assert record is not None and record.crypto_metadata is not None and user is not None
    assert user.password_hash != password and user.password_hash.startswith("$argon2id$")
    assert storage_service.read_bytes(record.storage_path) != b"private test content"
    assert len(record.crypto_metadata.wrapped_file_key) == 48
    keys = db_session.scalars(select(UserCryptoKey).where(UserCryptoKey.user_id == user.id)).all()
    assert keys and all(key.encrypted_private_key != key.public_key for key in keys)
    client.get(f"/api/files/{file_id}/download", headers=headers)
    logs = caplog.text
    for secret in (password, headers["Authorization"],
                   base64.b64encode(record.crypto_metadata.wrapped_file_key).decode(),
                   "private test content"):
        assert secret not in logs


@pytest.mark.parametrize("encoded", ["%%%", base64.urlsafe_b64encode(b"short").decode()])
def test_invalid_master_key_configuration_never_generates_fallback(encoded: str) -> None:
    configured = Settings(_env_file=None, database_url="sqlite+pysqlite:///:memory:",
                          secret_key="test-only-secret-key-more-than-thirty-two-bytes",
                          master_key_base64=encoded)
    with pytest.raises(ValueError, match="Invalid MASTER_KEY_BASE64 configuration"):
        _ = configured.master_key_bytes
