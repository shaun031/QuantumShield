"""Phase 11 ML-DSA identity, binding, legacy, and tamper regression tests."""

from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.signature_profiles import build_signature_profile_registry
from app.crypto.signature_payload import canonical_bytes, digest_bytes, package_digest
from app.models.digital_signature import DigitalSignature
from app.models.file import File
from app.models.file_share import FileShare
from app.models.user_crypto_key import UserCryptoKey
from app.services.crypto_keys import CryptoKeyService
from app.services.signatures import SignatureService
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login, upload
from tests.test_sharing import create_share


@pytest.mark.parametrize("algorithm", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
def test_native_provider_sign_verify_and_reject_tampering(algorithm: str) -> None:
    profile = build_signature_profile_registry().for_algorithm(algorithm)
    provider = profile.provider
    pair = provider.generate_keypair()
    signed = provider.sign(pair.private_key, b"canonical-message")
    assert len(pair.public_key) == provider.public_key_size
    assert len(pair.private_key) == 32
    assert len(signed) == provider.signature_size
    assert provider.verify(pair.public_key, b"canonical-message", signed)
    assert not provider.verify(pair.public_key, b"changed", signed)
    assert not provider.verify(pair.public_key, b"canonical-message", signed[:-1])
    wrong_pair = provider.generate_keypair()
    assert not provider.verify(wrong_pair.public_key, b"canonical-message", signed)
    assert provider.verify(pair.public_key, b"", provider.sign(pair.private_key, b""))


def test_canonical_json_is_stable_and_binary_digest_changes() -> None:
    left = {"z": [1, "é"], "a": {"next": None, "flag": True}}
    right = {"a": {"flag": True, "next": None}, "z": [1, "é"]}
    assert canonical_bytes(left) == canonical_bytes(right)
    assert b" " not in canonical_bytes(left)
    assert package_digest(left) == package_digest(right)
    assert digest_bytes(b"ciphertext A") != digest_bytes(b"ciphertext B")


def test_file_and_share_end_to_end_authenticity(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
) -> None:
    owner, owner_headers = register_and_login(client, "signed-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "signed-recipient@example.com")
    outsider, outsider_headers = register_and_login(client, "signed-outsider@example.com")
    content = b"signed and encrypted content"
    response = upload(client, owner_headers, content=content)
    assert response.status_code == 201
    file_id = response.json()["id"]
    assert response.json()["signature_required"] is True
    file_record = db_session.get(File, UUID(file_id))
    assert file_record is not None
    ciphertext = storage_service.read_bytes(file_record.storage_path)
    assert ciphertext != content
    signed_file = db_session.scalar(select(DigitalSignature).where(
        DigitalSignature.file_id == UUID(file_id), DigitalSignature.scope == "FILE"))
    assert signed_file is not None and len(signed_file.signature) == 3309
    assert signed_file.ciphertext_sha256 != file_record.sha256
    key = db_session.get(UserCryptoKey, signed_file.signing_key_id)
    assert key is not None and key.key_purpose == "SIGNATURE"
    assert key.user_id == UUID(owner["id"])
    assert client.get(f"/api/crypto/signing-key/{owner['id']}", headers=recipient_headers).json()["key_purpose"] == "SIGNATURE"

    verification = client.get(f"/api/files/{file_id}/verify", headers=owner_headers)
    assert verification.status_code == 200
    assert verification.json()["status"] == "VALID"
    assert verification.json()["algorithm"] == "ML-DSA-65"
    assert client.get(f"/api/files/{file_id}/verify", headers=outsider_headers).status_code == 404
    assert client.get(f"/api/files/{file_id}/download", headers=owner_headers).content == content

    shared = create_share(client, owner_headers, file_id, recipient["id"])
    assert shared.status_code == 201
    share_id = shared.json()["id"]
    assert shared.json()["signature_required"] is True
    assert storage_service.read_bytes(file_record.storage_path) == ciphertext
    assert client.get(f"/api/shares/{share_id}/verify", headers=recipient_headers).json()["status"] == "VALID"
    assert client.get(f"/api/shares/{share_id}/verify", headers=outsider_headers).status_code == 404
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).content == content


def test_file_metadata_and_ciphertext_tampering_fail_before_decryption(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "tamper-owner@example.com")
    file_id = upload(client, headers, content=b"private").json()["id"]
    record = db_session.get(File, UUID(file_id))
    record.original_filename = "substituted.txt"
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/verify", headers=headers).json()["status"] == "INVALID"
    denied = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert denied.status_code == 422 and denied.json()["detail"] == "Signature verification failed"

    db_session.refresh(record)
    record.original_filename = "report.txt"
    db_session.commit()
    path = storage_service.resolve_path(record.storage_path)
    ciphertext = bytearray(path.read_bytes())
    ciphertext[0] ^= 1
    path.write_bytes(ciphertext)
    assert client.get(f"/api/files/{file_id}/verify", headers=headers).json()["status"] == "INVALID"
    assert client.get(f"/api/files/{file_id}/download", headers=headers).status_code == 422


def test_required_missing_signature_fails_and_historical_unsigned_stays_readable(
    client: TestClient, db_session: Session,
) -> None:
    _, headers = register_and_login(client, "legacy-signed@example.com")
    content = b"legacy compatible"
    file_id = upload(client, headers, content=content).json()["id"]
    record = db_session.get(File, UUID(file_id))
    record.signatures.clear()
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/verify", headers=headers).json()["status"] == "INVALID"
    assert client.get(f"/api/files/{file_id}/download", headers=headers).status_code == 422
    record.signature_required = False
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/verify", headers=headers).json()["status"] == "LEGACY_UNSIGNED"
    assert client.get(f"/api/files/{file_id}/download", headers=headers).content == content


def test_share_recipient_and_envelope_tampering_fail(
    client: TestClient, db_session: Session,
) -> None:
    _, owner_headers = register_and_login(client, "share-tamper-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "share-tamper-recipient@example.com")
    file_id = upload(client, owner_headers, content=b"recipient bound").json()["id"]
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    share = db_session.get(FileShare, UUID(share_id))
    original = share.crypto_access.kem_ciphertext
    share.crypto_access.kem_ciphertext = bytes([original[0] ^ 1]) + original[1:]
    db_session.commit()
    assert client.get(f"/api/shares/{share_id}/verify", headers=recipient_headers).json()["status"] == "INVALID"
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).status_code == 422


def test_share_recipient_substitution_is_not_a_valid_sender_package(
    client: TestClient, db_session: Session,
) -> None:
    _, owner_headers = register_and_login(client, "recipient-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "recipient-original@example.com")
    substitute, substitute_headers = register_and_login(client, "recipient-substitute@example.com")
    file_id = upload(client, owner_headers, content=b"recipient identity").json()["id"]
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    share = db_session.get(FileShare, UUID(share_id))
    share.recipient_id = UUID(substitute["id"])
    db_session.commit()
    assert client.get(f"/api/shares/{share_id}/verify", headers=recipient_headers).status_code == 404
    result = client.get(f"/api/shares/{share_id}/verify", headers=substitute_headers)
    assert result.status_code == 200 and result.json()["status"] == "INVALID"
    assert client.get(f"/api/shares/{share_id}/download", headers=substitute_headers).status_code == 422


def test_wrong_signing_key_version_rejected(client: TestClient, db_session: Session) -> None:
    _, headers = register_and_login(client, "version-owner@example.com")
    file_id = upload(client, headers, content=b"versioned").json()["id"]
    signature = db_session.scalar(select(DigitalSignature).where(DigitalSignature.file_id == UUID(file_id)))
    signature.signing_key_version += 1
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/verify", headers=headers).json()["status"] == "INVALID"


def test_wrong_signer_key_binding_and_unknown_profile_rejected(
    client: TestClient, db_session: Session,
) -> None:
    _, owner_headers = register_and_login(client, "binding-owner@example.com")
    other, _ = register_and_login(client, "binding-other@example.com")
    file_id = upload(client, owner_headers, content=b"key bound").json()["id"]
    signature = db_session.scalar(select(DigitalSignature).where(DigitalSignature.file_id == UUID(file_id)))
    other_key = db_session.scalar(select(UserCryptoKey).where(
        UserCryptoKey.user_id == UUID(other["id"]), UserCryptoKey.key_purpose == "SIGNATURE"))
    signature.signing_key_id = other_key.id
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/verify", headers=owner_headers).json()["status"] == "INVALID"
    with pytest.raises(ValueError):
        build_signature_profile_registry().get("QS-SIG-UNKNOWN-V1")


@pytest.mark.parametrize("architecture", ["PQ_ONLY", "HYBRID"])
@pytest.mark.parametrize("level", ["LOW", "STANDARD", "HIGH"])
def test_signatures_are_independent_of_confidentiality_suite(
    client: TestClient, architecture: str, level: str,
) -> None:
    _, headers = register_and_login(client, f"{architecture.lower()}-{level.lower()}@example.com")
    response = client.post("/api/files/upload", headers=headers,
                           files={"file": ("suite.txt", b"suite signed", "text/plain")},
                           data={"selection_mode": "MANUAL", "security_level": level,
                                 "security_architecture": architecture})
    assert response.status_code == 201
    file_id = response.json()["id"]
    assert client.get(f"/api/files/{file_id}/verify", headers=headers).json()["status"] == "VALID"
    assert client.get(f"/api/files/{file_id}/download", headers=headers).content == b"suite signed"


def test_upload_signing_failure_rolls_back_and_removes_ciphertext(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers = register_and_login(client, "signing-failure@example.com")

    def fail_sign(*args, **kwargs):
        raise RuntimeError("test signing failure")

    monkeypatch.setattr(SignatureService, "sign_file", fail_sign)
    response = upload(client, headers, content=b"must not persist")
    assert response.status_code == 500
    assert db_session.scalar(select(File.id)) is None
    assert list(storage_service.root.rglob("*.enc")) == []


def test_invalid_file_signature_stops_before_private_key_recovery(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, headers = register_and_login(client, "early-reject@example.com")
    file_id = upload(client, headers, content=b"early rejection").json()["id"]
    record = db_session.get(File, UUID(file_id))
    record.mime_type = "application/x-substituted"
    db_session.commit()
    called = []

    def forbidden_recovery(*args, **kwargs):
        called.append(True)
        raise AssertionError("private key recovery occurred before signature check")

    monkeypatch.setattr(CryptoKeyService, "recover_private_key", forbidden_recovery)
    response = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert response.status_code == 422
    assert response.json()["detail"] == "Signature verification failed"
    assert called == []


def test_share_signing_failure_rolls_back_recipient_envelope(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, owner_headers = register_and_login(client, "share-failure-owner@example.com")
    recipient, _ = register_and_login(client, "share-failure-recipient@example.com")
    file_id = upload(client, owner_headers, content=b"original remains").json()["id"]

    def fail_sign(*args, **kwargs):
        raise RuntimeError("test share signing failure")

    monkeypatch.setattr(SignatureService, "sign_share", fail_sign)
    response = create_share(client, owner_headers, file_id, recipient["id"])
    assert response.status_code == 500
    assert db_session.scalar(select(FileShare.id)) is None
    assert db_session.scalar(select(DigitalSignature.id).where(DigitalSignature.scope == "SHARE")) is None
    assert client.get(f"/api/files/{file_id}/download", headers=owner_headers).content == b"original remains"


def test_signing_key_provisioning_is_idempotent(client: TestClient, db_session: Session) -> None:
    user, headers = register_and_login(client, "signing-provision@example.com")
    key = db_session.scalar(select(UserCryptoKey).where(
        UserCryptoKey.user_id == UUID(user["id"]), UserCryptoKey.key_purpose == "SIGNATURE"))
    original_id = key.id
    db_session.delete(key)
    db_session.commit()
    first = client.post("/api/crypto/keys/ensure", headers=headers)
    second = client.post("/api/crypto/keys/ensure", headers=headers)
    assert first.status_code == second.status_code == 200
    keys = [item for item in second.json() if item["key_purpose"] == "SIGNATURE"]
    assert len(keys) == 1
    assert keys[0]["id"] != str(original_id)


def test_new_upload_refuses_missing_signing_identity(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
) -> None:
    user, headers = register_and_login(client, "missing-signing@example.com")
    signing_key = db_session.scalar(select(UserCryptoKey).where(
        UserCryptoKey.user_id == UUID(user["id"]), UserCryptoKey.key_purpose == "SIGNATURE"))
    db_session.delete(signing_key)
    db_session.commit()
    response = upload(client, headers, content=b"not silently unsigned")
    assert response.status_code == 409
    assert db_session.scalar(select(File.id)) is None
    assert list(storage_service.root.rglob("*.enc")) == []
