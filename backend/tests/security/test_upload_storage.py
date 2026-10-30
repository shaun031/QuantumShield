"""Upload boundary, path confinement, object isolation, and cleanup."""

from pathlib import Path
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.file import File
from app.storage.local import InvalidStorageKeyError, LocalStorageService
from tests.test_files import register_and_login, upload


@pytest.mark.parametrize("filename", [
    "../../secret.txt", "..\\..\\secret.txt", "C:\\Windows\\system.ini",
    "/etc/passwd", "..\\storage\\file.txt", "%2e%2e%2fsecret.txt",
    "nested/../../file.txt", ".env", "report.final.pdf", "雪😀.txt",
    "<script>alert(1)</script>.txt", "$(echo harmless).txt",
])
def test_filename_cannot_select_storage_path(
    client: TestClient, db_session: Session, storage_service: LocalStorageService, filename: str,
) -> None:
    _, headers = register_and_login(client, "path-security@example.com")
    response = upload(client, headers, filename=filename, content=b"confined")
    assert response.status_code == 201
    record = db_session.get(File, UUID(response.json()["id"]))
    assert record is not None
    path = storage_service.resolve_path(record.storage_path)
    assert path.is_relative_to(storage_service.root)
    assert path.suffix == ".enc"
    assert path.read_bytes() != b"confined"
    assert client.get(f"/api/files/{record.id}/download", headers=headers).content == b"confined"


def test_empty_and_duplicate_uploads_are_independent(client: TestClient, db_session: Session) -> None:
    _, alice_h = register_and_login(client, "duplicate-alice@example.com")
    _, bob_h = register_and_login(client, "duplicate-bob@example.com")
    responses = [upload(client, alice_h, filename="report.pdf", content=b""),
                 upload(client, alice_h, filename="report.pdf", content=b"two"),
                 upload(client, bob_h, filename="report.pdf", content=b"three")]
    assert all(response.status_code == 201 for response in responses)
    records = [db_session.get(File, UUID(response.json()["id"])) for response in responses]
    assert all(record is not None for record in records)
    assert len({record.storage_path for record in records}) == 3
    assert client.get(f"/api/files/{responses[0].json()['id']}/download", headers=alice_h).content == b""


def test_oversize_leaves_no_record_or_object(
    client: TestClient, db_session: Session, storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "oversize-security@example.com")
    response = upload(client, headers, filename="large.zip", content=b"Z" * (1024 * 1024 + 1))
    assert response.status_code == 413
    assert db_session.scalar(select(func.count()).select_from(File)) == 0
    assert not [path for path in storage_service.root.rglob("*") if path.is_file()]


def test_mime_is_advisory_not_malware_detection(client: TestClient) -> None:
    _, headers = register_and_login(client, "mime-security@example.com")
    response = upload(client, headers, filename="renamed.pdf", content=b"MZ test bytes", mime_type="application/pdf")
    assert response.status_code == 201
    assert response.json()["mime_type"] == "application/pdf"
    assert client.get(f"/api/files/{response.json()['id']}/download", headers=headers).content == b"MZ test bytes"


@pytest.mark.parametrize("key", ["../outside.enc", "/tmp/outside.enc", "owner/../../outside.enc"])
def test_internal_storage_keys_cannot_escape_root(tmp_path: Path, key: str) -> None:
    storage = LocalStorageService(tmp_path / "objects")
    with pytest.raises(InvalidStorageKeyError):
        storage.save_bytes(b"secret", key)
    assert not [path for path in tmp_path.rglob("*") if path.is_file()]


def test_orphan_object_is_not_served(client: TestClient, storage_service: LocalStorageService) -> None:
    _, headers = register_and_login(client, "orphan-security@example.com")
    storage_service.save_bytes(b"orphan ciphertext", "orphan/unknown.enc")
    response = client.get("/api/files", headers=headers)
    assert response.status_code == 200 and response.json() == []
    assert client.get("/api/files/orphan/unknown.enc", headers=headers).status_code == 404
