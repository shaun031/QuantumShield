"""Phase 10 end-to-end hybrid and fail-closed regression tests."""

from uuid import UUID
from uuid import uuid4
from dataclasses import replace
import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.crypto_metadata import CryptoMetadata
from app.models.file import File
from app.models.share_crypto_metadata import ShareCryptoMetadata
from app.models.user_crypto_key import UserCryptoKey
from app.storage.local import LocalStorageService
from app.api.dependencies import get_crypto_suite_registry
from app.crypto.hybrid_key_protection import HybridContext, HybridKeyProtector, HybridSecretCombiner
from app.crypto.key_agreement import X25519Provider
from app.crypto.kdf import HKDFService
from tests.test_files import register_and_login


def test_x25519_provider_agreement_and_invalid_encoding() -> None:
    provider = X25519Provider()
    alice, bob, charlie = (provider.generate_keypair() for _ in range(3))
    assert len(alice.public_key) == len(alice.private_key) == 32
    shared = provider.derive_shared_secret(alice.private_key, bob.public_key)
    assert len(shared) == 32
    assert shared == provider.derive_shared_secret(bob.private_key, alice.public_key)
    assert shared != provider.derive_shared_secret(charlie.private_key, alice.public_key)
    with pytest.raises(ValueError):
        provider.derive_shared_secret(alice.private_key, b"short")
    with pytest.raises(ValueError):
        provider.derive_shared_secret(alice.private_key, bytes(32))


def test_hybrid_combiner_depends_on_both_components_salt_and_context() -> None:
    kdf = HKDFService()
    args = (b"P" * 32, b"C" * 32)
    salt = b"S" * 32
    info = b"QuantumShield/test/context"
    derive = lambda pq, classical, selected_salt, selected_info: HybridSecretCombiner.derive(
        kdf, pq, classical, salt=selected_salt, info=selected_info)
    result = derive(*args, salt, info)
    assert len(result) == 32 and result == derive(*args, salt, info)
    assert result != derive(b"Q" * 32, args[1], salt, info)
    assert result != derive(args[0], b"D" * 32, salt, info)
    assert result != derive(*args, b"T" * 32, info)
    assert result != derive(*args, salt, info + b"2")


@pytest.mark.parametrize("level,size", [("LOW",512),("STANDARD",768),("HIGH",1024)])
def test_hybrid_upload_owner_and_share_round_trip(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    level: str, size: int
) -> None:
    owner, owner_headers = register_and_login(client, f"hybrid-owner-{size}@example.com")
    recipient, recipient_headers = register_and_login(client, f"hybrid-recipient-{size}@example.com")
    content = f"hybrid-{size}-content".encode()
    response = client.post("/api/files/upload", headers=owner_headers,
        data={"security_level": level, "security_architecture": "HYBRID"},
        files={"file": ("hybrid.txt", content, "text/plain")})
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["crypto_suite_id"] == f"QS-HYBRID-{size}-V1"
    assert item["crypto_version"] == 4
    assert item["security_architecture"] == "HYBRID"
    assert item["classical_algorithm"] == "X25519"
    assert client.get(f"/api/files/{item['id']}/download", headers=owner_headers).content == content
    record = db_session.get(File, UUID(item["id"]))
    assert record.crypto_metadata.ephemeral_public_key
    assert record.crypto_metadata.combiner_version == 1
    ciphertext_before = storage_service.read_bytes(record.storage_path)
    share = client.post(f"/api/files/{item['id']}/share", headers=owner_headers,
        json={"recipient_id": recipient["id"]})
    assert share.status_code == 201, share.text
    shared = share.json()
    assert shared["security_architecture"] == "HYBRID"
    assert shared["classical_algorithm"] == "X25519"
    assert storage_service.read_bytes(record.storage_path) == ciphertext_before
    assert client.get(f"/api/shares/{shared['id']}/download", headers=recipient_headers).content == content
    assert client.get(f"/api/files/{item['id']}/download", headers=recipient_headers).status_code == 404


def test_hybrid_missing_classical_key_does_not_downgrade(client: TestClient, db_session: Session) -> None:
    owner, headers = register_and_login(client, "hybrid-missing@example.com")
    key = db_session.query(UserCryptoKey).filter_by(user_id=UUID(owner["id"]), algorithm="X25519").one()
    key.is_active = False
    db_session.commit()
    response = client.post("/api/files/upload", headers=headers,
        data={"security_architecture":"HYBRID","security_level":"STANDARD"},
        files={"file":("missing.txt",b"sensitive","text/plain")})
    assert response.status_code == 409
    assert db_session.query(File).count() == 0


def test_hybrid_tampered_ephemeral_public_key_fails_closed(client: TestClient, db_session: Session) -> None:
    _, headers = register_and_login(client, "hybrid-tamper@example.com")
    response = client.post("/api/files/upload", headers=headers,
        data={"security_architecture":"HYBRID","security_level":"LOW"},
        files={"file":("tamper.txt",b"tamper check","text/plain")})
    assert response.status_code == 201, response.text
    file_id = response.json()["id"]
    meta = db_session.query(CryptoMetadata).filter_by(file_id=UUID(file_id)).one()
    meta.ephemeral_public_key = bytes([meta.ephemeral_public_key[0] ^ 1]) + meta.ephemeral_public_key[1:]
    db_session.commit()
    assert client.get(f"/api/files/{file_id}/download", headers=headers).status_code == 422


def test_hybrid_component_and_transcript_failures() -> None:
    suites = get_crypto_suite_registry()
    agreement = X25519Provider()
    protector = HybridKeyProtector(suites, agreement)
    suite = suites.get_suite("QS-HYBRID-768-V1")
    pq = suite.kem.generate_keypair()
    classical = agreement.generate_keypair()
    owner = uuid4()
    context = HybridContext("OWNER", uuid4(), owner, owner, uuid4(), 1, uuid4(), 1,
                            suite.suite_id, 1, "STANDARD", 32, 4, 4)
    protected = protector.protect(b"F" * 32, pq.public_key, classical.public_key, context)
    inputs = dict(kem_private_key=pq.private_key, classical_private_key=classical.private_key,
                  classical_public_key=classical.public_key,
                  ephemeral_public_key=protected.ephemeral_public_key,
                  kem_ciphertext=protected.kem_ciphertext, kdf_salt=protected.kdf_salt,
                  wrapped_file_key=protected.wrapped_file_key,
                  key_wrap_nonce=protected.key_wrap_nonce, context=context)
    assert protector.recover(**inputs) == b"F" * 32
    wrong_pq = suite.kem.generate_keypair()
    wrong_classical = agreement.generate_keypair()
    cases = (
        {"kem_private_key": wrong_pq.private_key},
        {"classical_private_key": wrong_classical.private_key},
        {"kem_ciphertext": bytes([protected.kem_ciphertext[0] ^ 1]) + protected.kem_ciphertext[1:]},
        {"kdf_salt": bytes([protected.kdf_salt[0] ^ 1]) + protected.kdf_salt[1:]},
        {"context": replace(context, recipient_classical_key_id=uuid4())},
        {"context": replace(context, suite_id="QS-HYBRID-512-V1")},
        {"context": replace(context, crypto_version=3)},
    )
    for change in cases:
        with pytest.raises(ValueError):
            protector.recover(**{**inputs, **change})


def test_hybrid_share_tamper_fails_closed(client: TestClient, db_session: Session) -> None:
    owner, owner_headers = register_and_login(client, "hybrid-share-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "hybrid-share-recipient@example.com")
    uploaded = client.post("/api/files/upload", headers=owner_headers,
        data={"security_architecture":"HYBRID","security_level":"STANDARD"},
        files={"file":("shared.txt",b"shared hybrid bytes","text/plain")})
    assert uploaded.status_code == 201
    shared = client.post(f"/api/files/{uploaded.json()['id']}/share", headers=owner_headers,
        json={"recipient_id":recipient["id"]})
    assert shared.status_code == 201
    metadata = db_session.query(ShareCryptoMetadata).filter_by(file_share_id=UUID(shared.json()["id"])).one()
    metadata.ephemeral_public_key = bytes([metadata.ephemeral_public_key[0] ^ 1]) + metadata.ephemeral_public_key[1:]
    db_session.commit()
    assert client.get(f"/api/shares/{shared.json()['id']}/download", headers=recipient_headers).status_code == 422


def test_hybrid_share_missing_recipient_classical_key_has_no_fallback(
    client: TestClient, db_session: Session
) -> None:
    _, owner_headers = register_and_login(client, "hybrid-downgrade-owner@example.com")
    recipient, _ = register_and_login(client, "hybrid-downgrade-recipient@example.com")
    uploaded = client.post("/api/files/upload", headers=owner_headers,
        data={"security_architecture":"HYBRID","security_level":"HIGH"},
        files={"file":("private.txt",b"private","text/plain")})
    assert uploaded.status_code == 201
    key = db_session.query(UserCryptoKey).filter_by(user_id=UUID(recipient["id"]), algorithm="X25519").one()
    key.is_active = False
    db_session.commit()
    share = client.post(f"/api/files/{uploaded.json()['id']}/share", headers=owner_headers,
        json={"recipient_id":recipient["id"]})
    assert share.status_code == 409
    assert db_session.query(ShareCryptoMetadata).count() == 0


def test_hybrid_auto_keeps_policy_level(client: TestClient) -> None:
    _, headers = register_and_login(client, "hybrid-auto@example.com")
    preview = client.post("/api/security/recommend", headers=headers,
        json={"file_name":"report.txt","file_size":4,"sensitivity":"CONFIDENTIAL",
              "security_architecture":"HYBRID"})
    assert preview.status_code == 200
    assert preview.json()["recommended_level"] == "HIGH"
    assert preview.json()["crypto_suite_id"] == "QS-HYBRID-1024-V1"
    uploaded = client.post("/api/files/upload", headers=headers,
        data={"selection_mode":"AUTO","sensitivity":"CONFIDENTIAL",
              "security_architecture":"HYBRID"},
        files={"file":("report.txt",b"data","text/plain")})
    assert uploaded.status_code == 201, uploaded.text
    assert uploaded.json()["security_level"] == "HIGH"
    assert uploaded.json()["crypto_suite_id"] == "QS-HYBRID-1024-V1"


def test_existing_user_x25519_provisioning_is_idempotent(client: TestClient, db_session: Session) -> None:
    user, headers = register_and_login(client, "hybrid-existing@example.com")
    key = db_session.query(UserCryptoKey).filter_by(user_id=UUID(user["id"]), algorithm="X25519").one()
    original_id = key.id
    db_session.delete(key)
    db_session.commit()
    first = client.post("/api/crypto/keys/ensure", headers=headers)
    second = client.post("/api/crypto/keys/ensure", headers=headers)
    assert first.status_code == second.status_code == 200
    assert len(first.json()) == len(second.json()) == 5
    replacement = db_session.query(UserCryptoKey).filter_by(user_id=UUID(user["id"]), algorithm="X25519").one()
    assert replacement.id != original_id
    assert sum(item["algorithm"] == "X25519" for item in second.json()) == 1
    lookup = client.get(f"/api/crypto/public-key/{user['id']}?algorithm=X25519", headers=headers)
    assert lookup.status_code == 200
    assert len(base64.b64decode(lookup.json()["public_key_base64"])) == 32
    assert "private_key" not in lookup.text
