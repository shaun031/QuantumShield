"""Phase 6 sharing authorization, envelope integrity, and lifecycle tests."""

from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.crypto.aes import AESService
from app.crypto.kdf import HKDFService
from app.crypto.kem.mlkem import MLKEM768Provider
from app.crypto.kem.registry import KEMRegistry
from app.crypto.share_key_protection import (
    MLKEMShareKeyProtector,
    ShareKeyContext,
    ShareKeyProtectionError,
)
from app.models.file import File
from app.models.file_share import FileShare
from app.models.share_crypto_metadata import ShareCryptoMetadata
from app.models.user_crypto_key import UserCryptoKey
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login, upload


def create_share(
    client: TestClient,
    owner_headers: dict[str, str],
    file_id: str,
    recipient_id: str,
):
    return client.post(
        f"/api/files/{file_id}/share",
        headers=owner_headers,
        json={"recipient_id": recipient_id},
    )


def test_share_uses_one_unchanged_ciphertext_and_recipient_downloads(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    alice, alice_headers = register_and_login(client, "alice@example.com")
    bob, bob_headers = register_and_login(client, "bob@example.com")
    content = b"one encrypted object, multiple recipient envelopes"
    uploaded = upload(client, alice_headers, content=content).json()
    file_record = db_session.get(File, UUID(uploaded["id"]))
    assert file_record is not None
    object_path = storage_service.resolve_path(file_record.storage_path)
    before = object_path.read_bytes()
    before_files = [path for path in storage_service.root.rglob("*") if path.is_file()]

    response = create_share(client, alice_headers, uploaded["id"], bob["id"])

    assert response.status_code == 201
    body = response.json()
    assert body["sender"]["id"] == alice["id"]
    assert body["recipient"]["id"] == bob["id"]
    assert body["file"]["id"] == uploaded["id"]
    assert body["permission"] == "READ"
    assert body["status"] == "ACTIVE"
    assert body["kem_algorithm"] == "ML-KEM-768"
    assert body["crypto_suite_id"] == "QS-PQ-768-V1"
    assert "wrapped_file_key" not in response.text
    assert object_path.read_bytes() == before
    assert [path for path in storage_service.root.rglob("*") if path.is_file()] == before_files
    assert db_session.scalar(select(func.count()).select_from(File)) == 1
    assert db_session.scalar(select(func.count()).select_from(FileShare)) == 1
    assert db_session.scalar(select(func.count()).select_from(ShareCryptoMetadata)) == 1

    received = client.get("/api/shares/received", headers=bob_headers)
    sent = client.get("/api/shares/sent", headers=alice_headers)
    download = client.get(f"/api/shares/{body['id']}/download", headers=bob_headers)

    assert received.status_code == 200 and received.json()[0]["id"] == body["id"]
    assert sent.status_code == 200 and sent.json()[0]["id"] == body["id"]
    assert download.status_code == 200
    assert download.content == content


def test_share_authorization_self_duplicate_and_idor(client: TestClient) -> None:
    alice, alice_headers = register_and_login(client, "alice@example.com")
    bob, bob_headers = register_and_login(client, "bob@example.com")
    _, mallory_headers = register_and_login(client, "mallory@example.com")
    uploaded = upload(client, alice_headers).json()

    self_share = create_share(client, alice_headers, uploaded["id"], alice["id"])
    missing_recipient = create_share(client, alice_headers, uploaded["id"], str(uuid4()))
    created = create_share(client, alice_headers, uploaded["id"], bob["id"])
    duplicate = create_share(client, alice_headers, uploaded["id"], bob["id"])
    bob_reshare = create_share(client, bob_headers, uploaded["id"], alice["id"])
    share_id = created.json()["id"]

    assert self_share.status_code == 400
    assert missing_recipient.status_code == 404
    assert created.status_code == 201
    assert duplicate.status_code == 409
    assert bob_reshare.status_code == 404
    assert client.get(f"/api/shares/{share_id}", headers=alice_headers).status_code == 200
    assert client.get(f"/api/shares/{share_id}/download", headers=alice_headers).status_code == 404
    assert client.get(f"/api/shares/{share_id}", headers=mallory_headers).status_code == 404
    assert client.get(f"/api/shares/{share_id}/download", headers=mallory_headers).status_code == 404
    assert client.delete(f"/api/files/{uploaded['id']}", headers=bob_headers).status_code == 404


def test_recipient_without_active_key_is_rejected(
    client: TestClient,
    db_session: Session,
) -> None:
    _, alice_headers = register_and_login(client, "alice@example.com")
    bob, _ = register_and_login(client, "bob@example.com")
    uploaded = upload(client, alice_headers).json()
    key = db_session.scalar(
        select(UserCryptoKey).where(
            UserCryptoKey.user_id == UUID(bob["id"]),
            UserCryptoKey.algorithm == "ML-KEM-768",
        )
    )
    assert key is not None
    key.is_active = False
    db_session.commit()

    response = create_share(client, alice_headers, uploaded["id"], bob["id"])

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Recipient does not have an active ML-KEM-768 key"
    }


def test_tampered_share_envelope_and_ciphertext_fail_safely(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, alice_headers = register_and_login(client, "alice@example.com")
    bob, bob_headers = register_and_login(client, "bob@example.com")
    content = b"never disclose plaintext after tampering"
    first_file = upload(client, alice_headers, content=content).json()
    first_share = create_share(client, alice_headers, first_file["id"], bob["id"]).json()
    access = db_session.scalar(
        select(ShareCryptoMetadata).where(
            ShareCryptoMetadata.file_share_id == UUID(first_share["id"])
        )
    )
    assert access is not None
    modified = bytearray(access.kem_ciphertext)
    modified[0] ^= 1
    access.kem_ciphertext = bytes(modified)
    db_session.commit()

    envelope_response = client.get(
        f"/api/shares/{first_share['id']}/download", headers=bob_headers
    )
    assert envelope_response.status_code == 422
    assert content not in envelope_response.content

    second_file = upload(client, alice_headers, content=content).json()
    second_share = create_share(client, alice_headers, second_file["id"], bob["id"]).json()
    record = db_session.get(File, UUID(second_file["id"]))
    assert record is not None
    path = storage_service.resolve_path(record.storage_path)
    ciphertext = bytearray(path.read_bytes())
    ciphertext[-1] ^= 1
    path.write_bytes(ciphertext)

    ciphertext_response = client.get(
        f"/api/shares/{second_share['id']}/download", headers=bob_headers
    )
    owner_ciphertext_response = client.get(
        f"/api/files/{second_file['id']}/download", headers=alice_headers
    )
    assert ciphertext_response.status_code == 422
    assert owner_ciphertext_response.status_code == 422
    assert content not in ciphertext_response.content


def test_owner_delete_cascades_shares_envelopes_and_object(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, alice_headers = register_and_login(client, "alice@example.com")
    bob, bob_headers = register_and_login(client, "bob@example.com")
    uploaded = upload(client, alice_headers).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None
    object_key = record.storage_path
    share = create_share(client, alice_headers, uploaded["id"], bob["id"]).json()

    response = client.delete(f"/api/files/{uploaded['id']}", headers=alice_headers)

    assert response.status_code == 204
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(FileShare)) == 0
    assert db_session.scalar(select(func.count()).select_from(ShareCryptoMetadata)) == 0
    assert not storage_service.exists(object_key)
    assert client.get(f"/api/shares/{share['id']}", headers=bob_headers).status_code == 404


def test_authenticated_user_search_is_bounded_and_privacy_safe(client: TestClient) -> None:
    alice, alice_headers = register_and_login(client, "alice@example.com")
    bob, _ = register_and_login(client, "bobby@example.com")
    register_and_login(client, "robert@example.com")

    assert client.get("/api/users/search?q=bob").status_code == 401
    assert client.get("/api/users/search?q=ab", headers=alice_headers).status_code == 422
    assert client.get("/api/users/search?q=%20%20%20", headers=alice_headers).status_code == 422
    wildcard = client.get("/api/users/search?q=%25%25%25", headers=alice_headers)
    assert wildcard.status_code == 200 and wildcard.json() == []
    response = client.get("/api/users/search?q=bob&limit=1", headers=alice_headers)

    assert response.status_code == 200
    assert len(response.json()) == 1
    result = response.json()[0]
    assert result["id"] == bob["id"]
    assert result["id"] != alice["id"]
    assert set(result) == {
        "id", "name", "email", "crypto_ready", "supported_kem_algorithms", "supported_key_algorithms"
    }
    assert result["crypto_ready"] is True
    assert result["supported_kem_algorithms"] == [
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
    ]
    assert result["supported_key_algorithms"] == [
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519", "ML-DSA-65"
    ]


def test_share_envelope_is_bound_to_exact_recipient_and_context() -> None:
    provider = MLKEM768Provider()
    protector = MLKEMShareKeyProtector(
        KEMRegistry((provider,)), HKDFService(), AESService()
    )
    alice = provider.generate_keypair()
    bob = provider.generate_keypair()
    common = {
        "file_id": uuid4(),
        "owner_id": uuid4(),
        "plaintext_size": 42,
        "kem_algorithm": provider.algorithm_id,
    }
    alice_context = ShareKeyContext(
        share_id=uuid4(),
        recipient_id=uuid4(),
        recipient_key_id=uuid4(),
        recipient_key_version=2,
        **common,
    )
    bob_context = ShareKeyContext(
        share_id=uuid4(),
        recipient_id=uuid4(),
        recipient_key_id=uuid4(),
        recipient_key_version=3,
        **common,
    )
    file_key = AESService().generate_key()
    alice_access = protector.protect(file_key, alice.public_key, alice_context)
    bob_access = protector.protect(file_key, bob.public_key, bob_context)

    def recover(private_key: bytes, protected, context: ShareKeyContext) -> bytes:
        return protector.recover(
            recipient_private_key=private_key,
            kem_ciphertext=protected.kem_ciphertext,
            kdf_salt=protected.kdf_salt,
            wrapped_file_key=protected.wrapped_file_key,
            key_wrap_nonce=protected.key_wrap_nonce,
            kdf_algorithm=protected.kdf_algorithm,
            key_wrap_algorithm=protected.key_wrap_algorithm,
            context=context,
        )

    assert recover(alice.private_key, alice_access, alice_context) == file_key
    assert recover(bob.private_key, bob_access, bob_context) == file_key
    assert alice_access.kem_ciphertext != bob_access.kem_ciphertext
    assert alice_access.kdf_salt != bob_access.kdf_salt
    assert alice_access.wrapped_file_key != bob_access.wrapped_file_key
    with pytest.raises(ShareKeyProtectionError):
        recover(alice.private_key, bob_access, bob_context)
    with pytest.raises(ShareKeyProtectionError):
        recover(bob.private_key, alice_access, alice_context)
