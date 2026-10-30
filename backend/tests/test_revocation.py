"""Phase 12 lifecycle, authorization, audit, and crypto-freshness tests."""

from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog
from app.models.digital_signature import DigitalSignature
from app.models.file import File
from app.models.file_share import FileShare
from app.models.share_crypto_metadata import ShareCryptoMetadata
from app.repositories.audit import AuditRepository
from app.services.crypto_keys import CryptoKeyService
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login, upload
from tests.test_sharing import create_share


def revoke(client: TestClient, headers: dict[str, str], share_id: str,
           reason: str | None = None):
    return client.post(f"/api/shares/{share_id}/revoke", headers=headers,
                       json={"reason": reason})


def test_owner_revocation_is_idempotent_audited_and_precedes_crypto(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, owner_headers = register_and_login(client, "revoke-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "revoke-recipient@example.com")
    _, outsider_headers = register_and_login(client, "revoke-outsider@example.com")
    contents = b"already downloaded data remains with recipient"
    file_id = upload(client, owner_headers, content=contents).json()["id"]
    file_record = db_session.get(File, UUID(file_id))
    ciphertext = storage_service.read_bytes(file_record.storage_path)
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).content == contents
    assert revoke(client, recipient_headers, share_id).status_code == 404
    assert revoke(client, outsider_headers, share_id).status_code == 404

    first = revoke(client, owner_headers, share_id, "  Access no longer required  ")
    second = revoke(client, owner_headers, share_id, "ignored on retry")
    assert first.status_code == second.status_code == 200
    assert first.json()["status"] == second.json()["status"] == "REVOKED"
    assert first.json()["revoked_at"] is not None
    assert first.json()["revoked_at"] == second.json()["revoked_at"]
    assert first.json()["revoke_reason"] == "Access no longer required"
    db_session.expire_all()
    share = db_session.get(FileShare, UUID(share_id))
    assert share.revoked_by_user_id == UUID(owner["id"])
    assert share.revoke_reason == "Access no longer required"
    assert share.crypto_access.is_active is False
    assert storage_service.read_bytes(file_record.storage_path) == ciphertext
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.share_id == share.id, AuditLog.event_type == "SHARE_REVOKED")) == 1
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.share_id == share.id, AuditLog.event_type == "SHARE_CREATED")) == 1
    assert client.get(f"/api/shares/{share_id}/verify", headers=recipient_headers).json()["status"] == "VALID"
    assert client.get(f"/api/shares/{share_id}", headers=recipient_headers).json()["status"] == "REVOKED"
    assert client.get(f"/api/shares/{share_id}", headers=recipient_headers).json()["revoke_reason"] is None
    assert client.get("/api/shares/received", headers=recipient_headers).json()[0]["status"] == "REVOKED"
    assert client.get("/api/shares/sent", headers=owner_headers).json()[0]["status"] == "REVOKED"
    assert client.get("/api/shares/sent", headers=owner_headers).json()[0]["revoke_reason"] == "Access no longer required"

    called = []

    def forbidden_recovery(*args, **kwargs):
        called.append(True)
        raise AssertionError("private-key recovery after revocation")

    monkeypatch.setattr(CryptoKeyService, "recover_private_key", forbidden_recovery)
    denied = client.get(f"/api/shares/{share_id}/download", headers=recipient_headers)
    assert denied.status_code == 403
    assert denied.json() == {"detail": "Access to this shared file has been revoked."}
    assert called == []
    db_session.expire_all()
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.share_id == share.id,
        AuditLog.event_type == "SHARE_DOWNLOAD_DENIED_REVOKED")) == 1


@pytest.mark.parametrize("architecture", ["PQ_ONLY", "HYBRID"])
def test_reshare_uses_new_grant_envelope_and_signature(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
    architecture: str,
) -> None:
    _, owner_headers = register_and_login(client, f"reshare-{architecture}-owner@example.com")
    recipient, recipient_headers = register_and_login(client, f"reshare-{architecture}-recipient@example.com")
    response = client.post("/api/files/upload", headers=owner_headers,
                           files={"file": ("fresh.txt", b"same ciphertext", "text/plain")},
                           data={"security_architecture": architecture,
                                 "security_level": "STANDARD", "selection_mode": "MANUAL"})
    assert response.status_code == 201
    file_id = response.json()["id"]
    file_record = db_session.get(File, UUID(file_id))
    ciphertext = storage_service.read_bytes(file_record.storage_path)
    first = create_share(client, owner_headers, file_id, recipient["id"])
    assert first.status_code == 201
    first_id = first.json()["id"]
    duplicate = create_share(client, owner_headers, file_id, recipient["id"])
    assert duplicate.status_code == 409
    db_session.expire_all()
    first_access = db_session.scalar(select(ShareCryptoMetadata).where(
        ShareCryptoMetadata.file_share_id == UUID(first_id)))
    old_package = (first_access.kem_ciphertext, first_access.kdf_salt,
                   first_access.key_wrap_nonce, first_access.ephemeral_public_key)
    old_signature = db_session.scalar(select(DigitalSignature).where(
        DigitalSignature.file_share_id == UUID(first_id))).signature

    assert revoke(client, owner_headers, first_id).status_code == 200
    second = create_share(client, owner_headers, file_id, recipient["id"])
    assert second.status_code == 201
    second_id = second.json()["id"]
    assert second_id != first_id
    db_session.expire_all()
    second_access = db_session.scalar(select(ShareCryptoMetadata).where(
        ShareCryptoMetadata.file_share_id == UUID(second_id)))
    assert second_access.is_active is True
    assert second_access.kem_ciphertext != old_package[0]
    assert second_access.kdf_salt != old_package[1]
    assert second_access.key_wrap_nonce != old_package[2]
    if architecture == "HYBRID":
        assert second_access.ephemeral_public_key != old_package[3]
    second_signature = db_session.scalar(select(DigitalSignature).where(
        DigitalSignature.file_share_id == UUID(second_id))).signature
    assert second_signature != old_signature
    assert client.get(f"/api/shares/{first_id}/verify", headers=recipient_headers).json()["status"] == "VALID"
    assert client.get(f"/api/shares/{second_id}/verify", headers=recipient_headers).json()["status"] == "VALID"
    assert client.get(f"/api/shares/{first_id}/download", headers=recipient_headers).status_code == 403
    assert client.get(f"/api/shares/{second_id}/download", headers=recipient_headers).content == b"same ciphertext"
    assert storage_service.read_bytes(file_record.storage_path) == ciphertext
    listed = client.get("/api/shares/received", headers=recipient_headers).json()
    assert {item["status"] for item in listed} == {"ACTIVE", "REVOKED"}
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.event_type == "SHARE_CREATED")) == 2


def test_lifecycle_mismatch_fails_closed(client: TestClient, db_session: Session) -> None:
    _, owner_headers = register_and_login(client, "mismatch-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "mismatch-recipient@example.com")
    file_id = upload(client, owner_headers, content=b"mismatch").json()["id"]
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    access = db_session.scalar(select(ShareCryptoMetadata).where(
        ShareCryptoMetadata.file_share_id == UUID(share_id)))
    access.is_active = False
    db_session.commit()
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).status_code == 422
    access.is_active = True
    db_session.commit()
    assert revoke(client, owner_headers, share_id).status_code == 200
    db_session.expire_all()
    access = db_session.get(ShareCryptoMetadata, access.id)
    access.is_active = True
    db_session.commit()
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).status_code == 403
    retry = client.post(f"/api/shares/{share_id}/revoke", headers=owner_headers)
    assert retry.status_code == 200
    db_session.expire_all()
    assert db_session.get(ShareCryptoMetadata, access.id).is_active is False
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.share_id == UUID(share_id), AuditLog.event_type == "SHARE_REVOKED")) == 1


def test_revocation_audit_marker_blocks_state_reactivation(
    client: TestClient, db_session: Session,
) -> None:
    _, owner_headers = register_and_login(client, "audit-marker-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "audit-marker-recipient@example.com")
    file_id = upload(client, owner_headers, content=b"old grant").json()["id"]
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    assert revoke(client, owner_headers, share_id).status_code == 200
    share = db_session.get(FileShare, UUID(share_id))
    share.status = "ACTIVE"
    share.revoked_at = None
    share.revoked_by_user_id = None
    share.crypto_access.is_active = True
    db_session.commit()
    denied = client.get(f"/api/shares/{share_id}/download", headers=recipient_headers)
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Access to this shared file has been revoked."


def test_reason_validation_and_revocation_rollback(
    client: TestClient, db_session: Session, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, owner_headers = register_and_login(client, "rollback-owner@example.com")
    recipient, _ = register_and_login(client, "rollback-recipient@example.com")
    file_id = upload(client, owner_headers, content=b"atomic").json()["id"]
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    assert revoke(client, owner_headers, share_id, "x" * 256).status_code == 422

    original_record = AuditRepository.record

    def fail_revocation_audit(self, event_type, **kwargs):
        if event_type == "SHARE_REVOKED":
            raise RuntimeError("audit insert failure")
        return original_record(self, event_type, **kwargs)

    monkeypatch.setattr(AuditRepository, "record", fail_revocation_audit)
    assert revoke(client, owner_headers, share_id).status_code == 500
    db_session.expire_all()
    share = db_session.get(FileShare, UUID(share_id))
    assert share.status == "ACTIVE"
    assert share.crypto_access.is_active is True
    assert share.revoked_at is None
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.event_type == "SHARE_REVOKED")) == 0


def test_legacy_unsigned_share_can_be_revoked(client: TestClient, db_session: Session) -> None:
    _, owner_headers = register_and_login(client, "legacy-revoke-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "legacy-revoke-recipient@example.com")
    file_id = upload(client, owner_headers, content=b"legacy share").json()["id"]
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    share = db_session.get(FileShare, UUID(share_id))
    share.signature = None
    share.signature_required = False
    db_session.commit()
    assert client.get(f"/api/shares/{share_id}/verify", headers=recipient_headers).json()["status"] == "LEGACY_UNSIGNED"
    assert revoke(client, owner_headers, share_id).status_code == 200
    assert client.get(f"/api/shares/{share_id}/verify", headers=recipient_headers).json()["status"] == "LEGACY_UNSIGNED"
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).status_code == 403


def test_file_deletion_cascades_live_shares_but_retains_audit(
    client: TestClient, db_session: Session,
) -> None:
    _, owner_headers = register_and_login(client, "delete-revoke-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "delete-revoke-recipient@example.com")
    file_id = upload(client, owner_headers, content=b"delete all grants").json()["id"]
    share_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    assert client.delete(f"/api/files/{file_id}", headers=owner_headers).status_code == 204
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).status_code == 404
    db_session.expire_all()
    assert db_session.get(FileShare, UUID(share_id)) is None
    assert db_session.scalar(select(func.count()).select_from(AuditLog).where(
        AuditLog.file_id == UUID(file_id), AuditLog.event_type == "FILE_DELETED")) == 1


@pytest.mark.parametrize("level", ["LOW", "STANDARD", "HIGH"])
def test_revocation_is_independent_of_security_level(
    client: TestClient, level: str,
) -> None:
    _, owner_headers = register_and_login(client, f"level-{level}-owner@example.com")
    recipient, recipient_headers = register_and_login(client, f"level-{level}-recipient@example.com")
    uploaded = client.post("/api/files/upload", headers=owner_headers,
                           files={"file": ("level.txt", b"level independent", "text/plain")},
                           data={"security_level": level, "selection_mode": "MANUAL"})
    assert uploaded.status_code == 201
    share_id = create_share(client, owner_headers, uploaded.json()["id"], recipient["id"]).json()["id"]
    assert revoke(client, owner_headers, share_id).status_code == 200
    assert client.get(f"/api/shares/{share_id}/download", headers=recipient_headers).status_code == 403


def test_auto_policy_share_revoke_and_reshare(client: TestClient) -> None:
    _, owner_headers = register_and_login(client, "auto-revoke-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "auto-revoke-recipient@example.com")
    uploaded = client.post("/api/files/upload", headers=owner_headers,
                           files={"file": ("auto.txt", b"adaptive", "text/plain")},
                           data={"selection_mode": "AUTO", "sensitivity": "CONFIDENTIAL"})
    assert uploaded.status_code == 201
    file_id = uploaded.json()["id"]
    first_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    assert revoke(client, owner_headers, first_id).status_code == 200
    second_id = create_share(client, owner_headers, file_id, recipient["id"]).json()["id"]
    assert second_id != first_id
    assert client.get(f"/api/shares/{second_id}/download", headers=recipient_headers).content == b"adaptive"
