"""Two-component hybrid dependence and revocation lifecycle regressions."""

from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.dependencies import get_crypto_suite_registry
from app.crypto.hybrid_key_protection import HybridContext, HybridKeyProtector
from app.crypto.key_agreement import X25519Provider
from app.models.file_share import FileShare
from app.models.file import File
from app.models.digital_signature import DigitalSignature
from app.storage.local import LocalStorageService
from sqlalchemy import select
from tests.test_files import register_and_login, upload
from tests.test_sharing import create_share


def test_hybrid_both_components_and_package_binding_required() -> None:
    registry = get_crypto_suite_registry()
    suite = registry.get_suite("QS-HYBRID-768-V1")
    agreement = X25519Provider()
    protector = HybridKeyProtector(registry, agreement)
    kem = suite.kem.generate_keypair()
    xkey = agreement.generate_keypair()
    wrong_kem = suite.kem.generate_keypair()
    wrong_xkey = agreement.generate_keypair()
    owner = uuid4()
    context = HybridContext("SHARE", uuid4(), owner, uuid4(), uuid4(), 1,
                            uuid4(), 1, suite.suite_id, 1, "STANDARD", 20, 3, 3, uuid4())
    first = protector.protect(b"F" * 32, kem.public_key, xkey.public_key, context)
    second = protector.protect(b"F" * 32, kem.public_key, xkey.public_key,
                               replace(context, share_id=uuid4()))
    base = dict(kem_private_key=kem.private_key, classical_private_key=xkey.private_key,
                classical_public_key=xkey.public_key, ephemeral_public_key=first.ephemeral_public_key,
                kem_ciphertext=first.kem_ciphertext, kdf_salt=first.kdf_salt,
                wrapped_file_key=first.wrapped_file_key, key_wrap_nonce=first.key_wrap_nonce,
                context=context)
    assert protector.recover(**base) == b"F" * 32
    changes = (
        {"kem_private_key": wrong_kem.private_key},
        {"classical_private_key": wrong_xkey.private_key},
        {"ephemeral_public_key": second.ephemeral_public_key},
        {"kem_ciphertext": second.kem_ciphertext},
        {"ephemeral_public_key": second.ephemeral_public_key, "kem_ciphertext": second.kem_ciphertext},
        {"context": replace(context, suite_id="QS-HYBRID-512-V1")},
    )
    for change in changes:
        with pytest.raises(ValueError):
            protector.recover(**{**base, **change})


def test_revoked_old_grant_stays_denied_after_fresh_share(client: TestClient, db_session: Session) -> None:
    _, owner_h = register_and_login(client, "revocation-owner-security@example.com")
    bob, bob_h = register_and_login(client, "revocation-bob-security@example.com")
    file_id = upload(client, owner_h, content=b"fresh grant only").json()["id"]
    old = create_share(client, owner_h, file_id, bob["id"]).json()["id"]
    assert client.get(f"/api/shares/{old}/download", headers=bob_h).content == b"fresh grant only"
    assert client.post(f"/api/shares/{old}/revoke", headers=owner_h).status_code == 200
    assert client.get(f"/api/shares/{old}/download", headers=bob_h).status_code == 403
    fresh = create_share(client, owner_h, file_id, bob["id"]).json()["id"]
    assert fresh != old
    assert client.get(f"/api/shares/{fresh}/download", headers=bob_h).content == b"fresh grant only"
    old_share = db_session.get(FileShare, UUID(old))
    fresh_share = db_session.get(FileShare, UUID(fresh))
    assert old_share is not None and fresh_share is not None
    assert old_share.crypto_access.kem_ciphertext != fresh_share.crypto_access.kem_ciphertext
    assert old_share.crypto_access.is_active is False
    assert client.get(f"/api/shares/{old}/download", headers=bob_h).status_code == 403


def test_deleted_file_removes_future_share_access(client: TestClient) -> None:
    _, owner_h = register_and_login(client, "delete-owner-security@example.com")
    bob, bob_h = register_and_login(client, "delete-bob-security@example.com")
    file_id = upload(client, owner_h).json()["id"]
    share_id = create_share(client, owner_h, file_id, bob["id"]).json()["id"]
    assert client.delete(f"/api/files/{file_id}", headers=owner_h).status_code == 204
    assert client.get(f"/api/shares/{share_id}/download", headers=bob_h).status_code == 404


def test_complete_local_attack_restore_and_reshare_flow(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
) -> None:
    _, alice_h = register_and_login(client, "flow-alice@example.com")
    bob, bob_h = register_and_login(client, "flow-bob@example.com")
    secret = b"phase sixteen normal and attack flow"
    file_id = upload(client, alice_h, content=secret).json()["id"]
    assert client.get(f"/api/files/{file_id}/download", headers=bob_h).status_code == 404
    first = create_share(client, alice_h, file_id, bob["id"]).json()["id"]
    assert client.get(f"/api/shares/{first}/verify", headers=bob_h).json()["status"] == "VALID"
    assert client.get(f"/api/shares/{first}/download", headers=bob_h).content == secret
    record = db_session.get(File, UUID(file_id))
    assert record is not None
    path = storage_service.resolve_path(record.storage_path)
    ciphertext = path.read_bytes()
    path.write_bytes(bytes([ciphertext[0] ^ 1]) + ciphertext[1:])
    assert client.get(f"/api/shares/{first}/download", headers=bob_h).status_code == 422
    path.write_bytes(ciphertext)
    signature = db_session.scalar(select(DigitalSignature).where(DigitalSignature.file_share_id == UUID(first)))
    assert signature is not None
    original_signature = signature.signature
    signature.signature = bytes([original_signature[0] ^ 1]) + original_signature[1:]
    db_session.commit()
    assert client.get(f"/api/shares/{first}/download", headers=bob_h).status_code == 422
    signature.signature = original_signature
    db_session.commit()
    assert client.post(f"/api/shares/{first}/revoke", headers=alice_h).status_code == 200
    assert client.get(f"/api/shares/{first}/download", headers=bob_h).status_code == 403
    second = create_share(client, alice_h, file_id, bob["id"]).json()["id"]
    assert second != first
    assert client.get(f"/api/shares/{second}/download", headers=bob_h).content == secret
    assert client.get("/api/users/me", headers={"Authorization": "Bearer malformed"}).status_code == 401
