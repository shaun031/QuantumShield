"""Encrypted file storage, ownership, integrity, and cleanup tests."""

import hashlib
from pathlib import Path
from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.crypto.aes import AESService
from app.crypto.encryption import CryptoContext, EncryptionService
from app.crypto.key_protection import MasterKeyWrapper
from app.models.crypto_metadata import CryptoMetadata
from app.models.file import File
from app.models.user import User
from app.storage.local import LocalStorageService


def register_and_login(client: TestClient, email: str) -> tuple[dict, dict[str, str]]:
    password = "StrongPassword123!"
    registered = client.post(
        "/api/auth/register",
        json={"name": email.split("@", 1)[0], "email": email, "password": password},
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


def upload(
    client: TestClient,
    headers: dict[str, str],
    *,
    filename: str = "report.txt",
    content: bytes = b"phase-three-content",
    mime_type: str = "text/plain",
):
    return client.post(
        "/api/files/upload",
        headers=headers,
        files={"file": (filename, content, mime_type)},
    )


def test_upload_requires_authentication(client: TestClient) -> None:
    response = upload(client, {})

    assert response.status_code == 401


def test_authenticated_upload_stores_safe_metadata_and_hash(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    registered, headers = register_and_login(client, "alice@example.com")
    content = b"known content for hashing"

    response = upload(client, headers, content=content)

    assert response.status_code == 201
    body = response.json()
    assert body["original_filename"] == "report.txt"
    assert body["file_size"] == len(content)
    assert body["mime_type"] == "text/plain"
    assert body["sha256"] == hashlib.sha256(content).hexdigest()
    assert body["is_encrypted"] is True
    assert body["encryption_algorithm"] == "AES-256-GCM"
    assert body["post_quantum_protected"] is True
    assert body["kem_algorithm"] == "ML-KEM-768"
    assert body["crypto_version"] == 3
    assert body["crypto_suite_id"] == "QS-PQ-768-V1"
    assert body["crypto_suite_version"] == 1
    assert "stored_filename" not in body
    assert "storage_path" not in body
    assert "owner_id" not in body

    record = db_session.get(File, UUID(body["id"]))
    assert record is not None
    assert str(record.owner_id) == registered["id"]
    assert record.original_filename == "report.txt"
    assert record.stored_filename != record.original_filename
    assert record.stored_filename.endswith(".enc")
    assert record.crypto_metadata is not None
    assert len(record.crypto_metadata.content_nonce) == 12
    assert len(record.crypto_metadata.key_wrap_nonce) == 12
    assert len(record.crypto_metadata.wrapped_file_key) == 48
    assert record.crypto_metadata.crypto_version == 3
    assert record.crypto_metadata.crypto_suite_id == "QS-PQ-768-V1"
    assert record.crypto_metadata.kem_algorithm == "ML-KEM-768"
    assert len(record.crypto_metadata.kem_ciphertext or b"") == 1088
    assert record.crypto_metadata.kdf_algorithm == "HKDF-SHA256"
    assert len(record.crypto_metadata.kdf_salt or b"") == 32
    assert record.crypto_metadata.recipient_key_id is not None
    assert record.crypto_metadata.recipient_key_version == 1
    ciphertext = storage_service.open_file(record.storage_path).read_bytes()
    assert ciphertext != content
    assert content not in ciphertext
    assert len(ciphertext) == len(content) + 16


def test_list_and_metadata_are_scoped_to_authenticated_owner(
    client: TestClient,
) -> None:
    _, alice_headers = register_and_login(client, "alice@example.com")
    _, bob_headers = register_and_login(client, "bob@example.com")
    alice_file = upload(client, alice_headers).json()
    bob_file = upload(client, bob_headers, filename="bob.txt").json()

    alice_list = client.get("/api/files", headers=alice_headers)
    bob_reads_alice = client.get(
        f"/api/files/{alice_file['id']}",
        headers=bob_headers,
    )

    assert alice_list.status_code == 200
    assert [item["id"] for item in alice_list.json()] == [alice_file["id"]]
    assert bob_file["id"] not in {item["id"] for item in alice_list.json()}
    assert bob_reads_alice.status_code == 404


def test_owner_can_download_exact_bytes_and_original_name(client: TestClient) -> None:
    _, headers = register_and_login(client, "alice@example.com")
    content = b"download me exactly"
    uploaded = upload(
        client,
        headers,
        filename="Quarterly Report.txt",
        content=content,
    ).json()

    response = client.get(
        f"/api/files/{uploaded['id']}/download",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.content == content
    assert "Quarterly%20Report.txt" in response.headers["content-disposition"]


def test_other_user_cannot_download_or_delete(client: TestClient) -> None:
    _, alice_headers = register_and_login(client, "alice@example.com")
    _, bob_headers = register_and_login(client, "bob@example.com")
    uploaded = upload(client, alice_headers).json()

    download = client.get(
        f"/api/files/{uploaded['id']}/download",
        headers=bob_headers,
    )
    delete = client.delete(
        f"/api/files/{uploaded['id']}",
        headers=bob_headers,
    )

    assert download.status_code == 404
    assert delete.status_code == 404
    assert client.get(
        f"/api/files/{uploaded['id']}",
        headers=alice_headers,
    ).status_code == 200


def test_owner_delete_removes_metadata_and_object(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "alice@example.com")
    uploaded = upload(client, headers).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None
    object_key = record.storage_path

    response = client.delete(f"/api/files/{uploaded['id']}", headers=headers)

    assert response.status_code == 204
    db_session.expire_all()
    assert db_session.get(File, UUID(uploaded["id"])) is None
    assert db_session.scalar(select(func.count()).select_from(CryptoMetadata)) == 0
    assert not storage_service.exists(object_key)


def test_duplicate_original_filenames_never_overwrite(
    client: TestClient,
    db_session: Session,
) -> None:
    _, headers = register_and_login(client, "alice@example.com")
    first = upload(client, headers, content=b"first").json()
    second = upload(client, headers, content=b"second").json()

    first_record = db_session.get(File, UUID(first["id"]))
    second_record = db_session.get(File, UUID(second["id"]))
    assert first_record is not None and second_record is not None
    assert first_record.original_filename == second_record.original_filename
    assert first_record.stored_filename != second_record.stored_filename
    assert first_record.storage_path != second_record.storage_path


def test_path_traversal_filename_cannot_escape_storage_root(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "alice@example.com")

    response = upload(client, headers, filename="../../evil.txt", content=b"safe")

    assert response.status_code == 201
    assert response.json()["original_filename"] == "evil.txt"
    record = db_session.get(File, UUID(response.json()["id"]))
    assert record is not None
    stored_path = storage_service.resolve_path(record.storage_path)
    assert stored_path.is_relative_to(storage_service.root)
    assert stored_path.suffix == ".enc"
    assert stored_path.read_bytes() != b"safe"
    assert not (storage_service.root.parent / "evil.txt").exists()


def test_oversized_upload_removes_partial_file_and_database_row(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "alice@example.com")
    oversized = b"x" * (1024 * 1024 + 1)

    response = upload(client, headers, filename="large.bin", content=oversized)

    assert response.status_code == 413
    assert db_session.scalar(select(func.count()).select_from(File)) == 0
    assert [path for path in storage_service.root.rglob("*") if path.is_file()] == []


def test_missing_physical_file_returns_404_but_owner_can_clean_metadata(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "alice@example.com")
    uploaded = upload(client, headers).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None
    storage_service.resolve_path(record.storage_path).unlink()

    download = client.get(
        f"/api/files/{uploaded['id']}/download",
        headers=headers,
    )
    delete = client.delete(f"/api/files/{uploaded['id']}", headers=headers)

    assert download.status_code == 404
    assert delete.status_code == 204
    db_session.expire_all()
    assert db_session.get(File, UUID(uploaded["id"])) is None


def test_pagination_bounds_are_enforced(client: TestClient) -> None:
    _, headers = register_and_login(client, "alice@example.com")

    assert client.get("/api/files?limit=0", headers=headers).status_code == 422
    assert client.get("/api/files?limit=101", headers=headers).status_code == 422
    assert client.get("/api/files?offset=-1", headers=headers).status_code == 422


def test_modified_ciphertext_returns_controlled_integrity_error(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "alice@example.com")
    content = b"authenticated content must never leak after tampering"
    uploaded = upload(client, headers, content=content).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None
    object_path = storage_service.resolve_path(record.storage_path)
    ciphertext = bytearray(object_path.read_bytes())
    ciphertext[-1] ^= 1
    object_path.write_bytes(ciphertext)

    response = client.get(
        f"/api/files/{uploaded['id']}/download",
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Signature verification failed"}
    assert content not in response.content


def test_modified_kem_ciphertext_returns_controlled_integrity_error(
    client: TestClient,
    db_session: Session,
) -> None:
    _, headers = register_and_login(client, "kem-tamper@example.com")
    content = b"KEM ciphertext tampering must not recover this plaintext"
    uploaded = upload(client, headers, content=content).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None and record.crypto_metadata is not None
    kem_ciphertext = bytearray(record.crypto_metadata.kem_ciphertext or b"")
    kem_ciphertext[0] ^= 1
    record.crypto_metadata.kem_ciphertext = bytes(kem_ciphertext)
    db_session.commit()

    response = client.get(
        f"/api/files/{uploaded['id']}/download",
        headers=headers,
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Signature verification failed"}
    assert content not in response.content


def test_legacy_plaintext_record_is_explicitly_blocked_until_migrated(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    registered, headers = register_and_login(client, "legacy@example.com")
    owner = db_session.get(User, UUID(registered["id"]))
    assert owner is not None
    plaintext = b"legacy phase three bytes"
    legacy = File(
        owner_id=owner.id,
        original_filename="legacy.txt",
        stored_filename="legacy-phase3.txt",
        storage_path=f"{owner.id}/legacy-phase3.txt",
        file_size=len(plaintext),
        mime_type="text/plain",
        sha256=hashlib.sha256(plaintext).hexdigest(),
    )
    db_session.add(legacy)
    db_session.commit()
    storage_service.save_bytes(plaintext, legacy.storage_path)

    metadata_response = client.get(f"/api/files/{legacy.id}", headers=headers)
    download_response = client.get(
        f"/api/files/{legacy.id}/download",
        headers=headers,
    )

    assert metadata_response.status_code == 200
    assert metadata_response.json()["is_encrypted"] is False
    assert metadata_response.json()["encryption_algorithm"] is None
    assert download_response.status_code == 409
    assert download_response.json() == {
        "detail": "Legacy plaintext file requires encryption migration"
    }


def test_phase4_crypto_version_one_file_remains_downloadable(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    registered, headers = register_and_login(client, "phase4@example.com")
    owner_id = UUID(registered["id"])
    plaintext = b"existing Phase 4 AES-GCM file"
    file_id = UUID("11111111-2222-4333-8444-555555555555")
    aes = AESService()
    legacy_encryption = EncryptionService(
        aes,
        MasterKeyWrapper(b"T" * 32, aes),
    )
    context = CryptoContext(
        file_id=file_id,
        owner_id=owner_id,
        plaintext_size=len(plaintext),
    )
    encrypted = legacy_encryption.encrypt_file(plaintext, context)
    record = File(
        id=file_id,
        owner_id=owner_id,
        original_filename="phase4.txt",
        stored_filename="phase4-version-one.enc",
        storage_path=f"{owner_id}/phase4-version-one.enc",
        file_size=len(plaintext),
        mime_type="text/plain",
        sha256=hashlib.sha256(plaintext).hexdigest(),
        crypto_metadata=CryptoMetadata(
            content_algorithm=encrypted.content_algorithm,
            content_nonce=encrypted.content_nonce,
            wrapped_file_key=encrypted.wrapped_file_key,
            key_wrap_algorithm=encrypted.key_wrap_algorithm,
            key_wrap_nonce=encrypted.key_wrap_nonce,
            crypto_version=encrypted.crypto_version,
            aad_version=encrypted.aad_version,
        ),
    )
    db_session.add(record)
    db_session.commit()
    storage_service.save_bytes(encrypted.ciphertext, record.storage_path)

    response = client.get(f"/api/files/{file_id}/download", headers=headers)

    assert response.status_code == 200
    assert response.content == plaintext
