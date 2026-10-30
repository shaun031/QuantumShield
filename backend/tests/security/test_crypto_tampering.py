"""Signed package, AES-GCM, KEM, hybrid, and suite fail-closed cases."""

from uuid import UUID, uuid4

import pytest
from cryptography.exceptions import InvalidTag
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import get_crypto_suite_registry
from app.crypto.aes import AESService
from app.crypto.kdf import HKDFService
from app.crypto.kem.mlkem import MLKEM768Provider
from app.crypto.kem.registry import KEMRegistry
from app.crypto.share_key_protection import MLKEMShareKeyProtector, ShareKeyContext, ShareKeyProtectionError
from app.models.digital_signature import DigitalSignature
from app.models.file import File
from app.models.file_share import FileShare
from app.models.user_crypto_key import UserCryptoKey
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login, upload
from tests.test_sharing import create_share


def flip(data: bytes) -> bytes:
    altered = bytearray(data)
    altered[0] ^= 1
    return bytes(altered)


@pytest.mark.parametrize("field", [
    "content_nonce", "wrapped_file_key", "key_wrap_nonce", "kem_ciphertext", "kdf_salt",
])
def test_owner_envelope_tamper_blocks_plaintext(
    client: TestClient, db_session: Session, field: str,
) -> None:
    _, headers = register_and_login(client, f"owner-{field}@example.com")
    secret = b"never emit this secret after corruption"
    file_id = upload(client, headers, content=secret).json()["id"]
    record = db_session.get(File, UUID(file_id))
    assert record is not None and record.crypto_metadata is not None
    metadata = record.crypto_metadata
    setattr(metadata, field, flip(getattr(metadata, field)))
    db_session.commit()
    response = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert response.status_code == 422
    assert secret not in response.content
    assert response.json() == {"detail": "Signature verification failed"}


@pytest.mark.parametrize("field", [
    "kem_ciphertext", "kdf_salt", "wrapped_file_key", "key_wrap_nonce",
])
def test_recipient_envelope_tamper_blocks_plaintext(
    client: TestClient, db_session: Session, field: str,
) -> None:
    _, alice_h = register_and_login(client, f"share-owner-{field}@example.com")
    bob, bob_h = register_and_login(client, f"share-bob-{field}@example.com")
    secret = b"recipient secret cannot leak"
    file_id = upload(client, alice_h, content=secret).json()["id"]
    share_id = create_share(client, alice_h, file_id, bob["id"]).json()["id"]
    share = db_session.get(FileShare, UUID(share_id))
    assert share is not None and share.crypto_access is not None
    access = share.crypto_access
    setattr(access, field, flip(getattr(access, field)))
    db_session.commit()
    response = client.get(f"/api/shares/{share_id}/download", headers=bob_h)
    assert response.status_code == 422
    assert secret not in response.content


def test_wrong_aes_key_nonce_and_ciphertext_rejected_without_partial_output() -> None:
    aes = AESService()
    key = aes.generate_key()
    protected = aes.encrypt(b"authenticated plaintext", key, b"bound context")
    for ciphertext, candidate_key, nonce in (
        (protected.ciphertext, aes.generate_key(), protected.nonce),
        (protected.ciphertext, key, flip(protected.nonce)),
        (flip(protected.ciphertext), key, protected.nonce),
    ):
        with pytest.raises(InvalidTag):
            aes.decrypt(ciphertext, candidate_key, nonce, b"bound context")


def test_ciphertext_replacement_and_truncation_rejected(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "replacement@example.com")
    first = upload(client, headers, content=b"first plaintext").json()["id"]
    second = upload(client, headers, content=b"second plaintext").json()["id"]
    first_record = db_session.get(File, UUID(first))
    second_record = db_session.get(File, UUID(second))
    assert first_record is not None and second_record is not None
    first_path = storage_service.resolve_path(first_record.storage_path)
    second_path = storage_service.resolve_path(second_record.storage_path)
    original = first_path.read_bytes()
    first_path.write_bytes(second_path.read_bytes())
    response = client.get(f"/api/files/{first}/download", headers=headers)
    assert response.status_code == 422 and b"second plaintext" not in response.content
    first_path.write_bytes(original[:8])
    assert client.get(f"/api/files/{first}/download", headers=headers).status_code == 422


@pytest.mark.parametrize("field", ["original_filename", "file_size", "mime_type", "sha256"])
def test_signed_file_metadata_change_rejected(
    client: TestClient, db_session: Session, field: str,
) -> None:
    _, headers = register_and_login(client, f"signed-{field}@example.com")
    file_id = upload(client, headers, content=b"signed content").json()["id"]
    record = db_session.get(File, UUID(file_id))
    assert record is not None
    replacement = {"original_filename": "evil.txt", "file_size": record.file_size + 1,
                   "mime_type": "application/evil", "sha256": "0" * 64}[field]
    setattr(record, field, replacement)
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/verify", headers=headers).json()["status"] == "INVALID"
    assert client.get(f"/api/files/{file_id}/download", headers=headers).status_code == 422


def test_signature_bytes_and_wrong_signing_key_rejected(client: TestClient, db_session: Session) -> None:
    alice, alice_h = register_and_login(client, "signature-alice@example.com")
    bob, _ = register_and_login(client, "signature-bob@example.com")
    file_id = upload(client, alice_h, content=b"authentic").json()["id"]
    signature = db_session.scalar(select(DigitalSignature).where(DigitalSignature.file_id == UUID(file_id)))
    assert signature is not None
    original = signature.signature
    signature.signature = flip(original)
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/download", headers=alice_h).status_code == 422
    signature.signature = original
    wrong_key = db_session.scalar(select(UserCryptoKey).where(
        UserCryptoKey.user_id == UUID(bob["id"]), UserCryptoKey.key_purpose == "SIGNATURE"))
    assert wrong_key is not None
    signature.signing_key_id = wrong_key.id
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/download", headers=alice_h).status_code == 422
    assert signature.signer_user_id == UUID(alice["id"])


def test_share_signature_and_package_swap_rejected(client: TestClient, db_session: Session) -> None:
    _, alice_h = register_and_login(client, "swap-alice@example.com")
    bob, bob_h = register_and_login(client, "swap-bob@example.com")
    charlie, _ = register_and_login(client, "swap-charlie@example.com")
    file_id = upload(client, alice_h, content=b"share integrity").json()["id"]
    bob_id = create_share(client, alice_h, file_id, bob["id"]).json()["id"]
    charlie_id = create_share(client, alice_h, file_id, charlie["id"]).json()["id"]
    bob_share = db_session.get(FileShare, UUID(bob_id))
    charlie_share = db_session.get(FileShare, UUID(charlie_id))
    assert bob_share is not None and charlie_share is not None
    assert bob_share.crypto_access is not None and charlie_share.crypto_access is not None
    bob_share.crypto_access.kem_ciphertext = charlie_share.crypto_access.kem_ciphertext
    db_session.commit()
    assert client.get(f"/api/shares/{bob_id}/download", headers=bob_h).status_code == 422


@pytest.mark.parametrize("suite_id", ["UNKNOWN-SUITE", "QS-PQ-512-V1"])
def test_unknown_or_mismatched_suite_never_falls_back(suite_id: str) -> None:
    registry = get_crypto_suite_registry()
    if suite_id == "UNKNOWN-SUITE":
        with pytest.raises(ValueError):
            registry.get_suite(suite_id, for_encryption=False)
    else:
        with pytest.raises(ValueError):
            registry.validate_metadata(
                suite_id=suite_id, suite_version=1, security_level="HIGH",
                content_algorithm="AES-256-GCM", kem_algorithm="ML-KEM-1024",
                kdf_algorithm="HKDF-SHA256", key_wrap_algorithm="KEK-AES-256-GCM",
                architecture="PQ_ONLY", classical_algorithm=None,
            )


def test_wrong_mlkem_private_key_and_changed_kdf_context_fail() -> None:
    kem = MLKEM768Provider()
    protector = MLKEMShareKeyProtector(KEMRegistry((kem,)), HKDFService(), AESService())
    bob = kem.generate_keypair()
    charlie = kem.generate_keypair()
    context = ShareKeyContext(
        share_id=uuid4(), file_id=uuid4(), owner_id=uuid4(), recipient_id=uuid4(),
        recipient_key_id=uuid4(), recipient_key_version=1, kem_algorithm=kem.algorithm_id,
        plaintext_size=20,
    )
    protected = protector.protect(b"K" * 32, bob.public_key, context)
    base = dict(recipient_private_key=bob.private_key,
                kem_ciphertext=protected.kem_ciphertext, kdf_salt=protected.kdf_salt,
                wrapped_file_key=protected.wrapped_file_key,
                key_wrap_nonce=protected.key_wrap_nonce,
                kdf_algorithm="HKDF-SHA256", key_wrap_algorithm="KEK-AES-256-GCM",
                context=context)
    assert protector.recover(**base) == b"K" * 32
    for change in ({"recipient_private_key": charlie.private_key},
                   {"kdf_salt": flip(protected.kdf_salt)},
                   {"kdf_algorithm": "UNKNOWN-KDF"},
                   {"context": ShareKeyContext(**{**vars(context), "recipient_id": uuid4()})}):
        with pytest.raises(ShareKeyProtectionError):
            protector.recover(**{**base, **change})


def test_unsupported_crypto_version_and_corrupt_private_blob_fail_closed(
    client: TestClient, db_session: Session,
) -> None:
    user, headers = register_and_login(client, "version-security@example.com")
    file_id = upload(client, headers, content=b"protected").json()["id"]
    record = db_session.get(File, UUID(file_id))
    assert record is not None and record.crypto_metadata is not None
    record.crypto_metadata.crypto_version = 99
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/download", headers=headers).status_code == 422
    record.crypto_metadata.crypto_version = 3
    db_session.commit()
    key = db_session.scalar(select(UserCryptoKey).where(
        UserCryptoKey.user_id == UUID(user["id"]), UserCryptoKey.algorithm == "ML-KEM-768"))
    assert key is not None
    key.encrypted_private_key = flip(key.encrypted_private_key)
    db_session.commit()
    response = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert response.status_code == 422
    assert b"protected" not in response.content
