"""Phase 8 API, crypto, privacy, and sharing integration tests."""

from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.file import File
from app.models.file_share import FileShare
from app.models.share_crypto_metadata import ShareCryptoMetadata
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login


def adaptive_upload(
    client: TestClient,
    headers: dict[str, str],
    *,
    filename: str,
    content: bytes,
    mode: str,
    sensitivity: str | None = None,
    category: str | None = None,
    level: str | None = None,
):
    data = {"selection_mode": mode}
    if sensitivity is not None:
        data["sensitivity"] = sensitivity
    if category is not None:
        data["document_category"] = category
    if level is not None:
        data["security_level"] = level
    return client.post(
        "/api/files/upload",
        headers=headers,
        data=data,
        files={"file": (filename, content, "application/octet-stream")},
    )


def test_security_options_and_recommendation_api(client: TestClient) -> None:
    _, headers = register_and_login(client, "policy-api@example.com")
    options = client.get("/api/security/options", headers=headers)
    recommendation = client.post(
        "/api/security/recommend",
        headers=headers,
        json={
            "file_name": "accounts.pdf",
            "file_size": 1000,
            "mime_type": "application/pdf",
            "sensitivity": "CONFIDENTIAL",
            "document_category": "FINANCIAL",
        },
    )

    assert options.status_code == 200
    assert options.json()["selection_modes"] == ["MANUAL", "RECOMMEND", "AUTO"]
    assert options.json()["policy_version"] == "adaptive-v1"
    assert [item["rank"] for item in options.json()["security_levels"]] == [1, 2, 3]
    assert recommendation.status_code == 200
    assert recommendation.json()["recommended_level"] == "HIGH"
    assert recommendation.json()["kem_algorithm"] == "ML-KEM-1024"
    assert recommendation.json()["crypto_suite_id"] == "QS-PQ-1024-V1"
    assert options.json()["security_levels"][0]["suite_id"] == "QS-PQ-512-V1"
    assert len(recommendation.json()["rules_triggered"]) == 2
    blank = client.post(
        "/api/security/recommend",
        headers=headers,
        json={"file_name": "   ", "file_size": 0},
    )
    assert blank.status_code == 422


@pytest.mark.parametrize(
    ("filename", "sensitivity", "category", "level", "algorithm"),
    [
        ("public_notes.txt", "PUBLIC", "GENERAL", "LOW", "ML-KEM-512"),
        ("project.docx", "INTERNAL", "ACADEMIC", "STANDARD", "ML-KEM-768"),
        ("accounts.pdf", "CONFIDENTIAL", "FINANCIAL", "HIGH", "ML-KEM-1024"),
        ("notice.txt", "PUBLIC", "MEDICAL", "HIGH", "ML-KEM-1024"),
        ("vault.txt", "HIGHLY_CONFIDENTIAL", "GENERAL", "HIGH", "ML-KEM-1024"),
    ],
)
def test_auto_policy_drives_real_crypto_round_trip(
    client: TestClient,
    filename: str,
    sensitivity: str,
    category: str,
    level: str,
    algorithm: str,
) -> None:
    _, headers = register_and_login(
        client, f"{filename.replace('.', '-')}-{category.lower()}@example.com"
    )
    content = f"adaptive bytes for {filename}".encode()
    response = adaptive_upload(
        client,
        headers,
        filename=filename,
        content=content,
        mode="AUTO",
        sensitivity=sensitivity,
        category=category,
    )

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["selection_mode"] == "AUTO"
    assert body["security_level"] == level
    assert body["kem_algorithm"] == algorithm
    assert body["crypto_suite_id"] == {
        "LOW": "QS-PQ-512-V1",
        "STANDARD": "QS-PQ-768-V1",
        "HIGH": "QS-PQ-1024-V1",
    }[level]
    assert body["policy_version"] == "adaptive-v1"
    assert body["decision_reasons"]
    download = client.get(f"/api/files/{body['id']}/download", headers=headers)
    assert download.status_code == 200 and download.content == content


def test_auto_without_signals_defaults_to_standard(client: TestClient) -> None:
    _, headers = register_and_login(client, "auto-default@example.com")
    response = adaptive_upload(
        client,
        headers,
        filename="ordinary.bin",
        content=b"default policy",
        mode="AUTO",
    )

    assert response.status_code == 201
    assert response.json()["security_level"] == "STANDARD"
    assert response.json()["kem_algorithm"] == "ML-KEM-768"
    assert "default project policy" in response.json()["decision_reasons"][0]


def test_recommend_accepts_increase_and_rejects_required_downgrade(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "recommend-override@example.com")
    increased = adaptive_upload(
        client,
        headers,
        filename="public.txt",
        content=b"increased",
        mode="RECOMMEND",
        sensitivity="PUBLIC",
        category="GENERAL",
        level="HIGH",
    )
    before_files = list(storage_service.root.rglob("*.enc"))
    before_rows = db_session.scalar(select(func.count()).select_from(File))
    rejected = adaptive_upload(
        client,
        headers,
        filename="confidential.txt",
        content=b"must not persist",
        mode="RECOMMEND",
        sensitivity="CONFIDENTIAL",
        category="GENERAL",
        level="LOW",
    )

    assert increased.status_code == 201
    assert increased.json()["recommended_security_level"] == "LOW"
    assert increased.json()["security_level"] == "HIGH"
    assert increased.json()["kem_algorithm"] == "ML-KEM-1024"
    assert increased.json()["user_override"] is True
    assert rejected.status_code == 422
    assert "below the policy-required HIGH" in rejected.json()["detail"]
    assert db_session.scalar(select(func.count()).select_from(File)) == before_rows
    assert list(storage_service.root.rglob("*.enc")) == before_files


def test_auto_rejects_explicit_level_and_invalid_enums(client: TestClient) -> None:
    _, headers = register_and_login(client, "invalid-policy@example.com")
    contradiction = adaptive_upload(
        client,
        headers,
        filename="auto.txt",
        content=b"contradiction",
        mode="AUTO",
        sensitivity="PUBLIC",
        category="GENERAL",
        level="LOW",
    )
    unknown = adaptive_upload(
        client,
        headers,
        filename="unknown.txt",
        content=b"unknown",
        mode="AUTO",
        sensitivity="SECRET",
        category="GENERAL",
    )

    assert contradiction.status_code == 422
    assert "does not accept an explicit security level" in contradiction.json()["detail"]
    assert unknown.status_code == 422


def test_decision_detail_is_owner_only_and_historical_rows_remain_readable(
    client: TestClient,
    db_session: Session,
) -> None:
    _, owner_headers = register_and_login(client, "decision-owner@example.com")
    _, other_headers = register_and_login(client, "decision-other@example.com")
    content = b"historical-compatible"
    uploaded = adaptive_upload(
        client,
        owner_headers,
        filename="decision.txt",
        content=content,
        mode="AUTO",
        sensitivity="INTERNAL",
        category="ACADEMIC",
    ).json()

    detail = client.get(
        f"/api/files/{uploaded['id']}/security-decision", headers=owner_headers
    )
    hidden = client.get(
        f"/api/files/{uploaded['id']}/security-decision", headers=other_headers
    )
    assert detail.status_code == 200
    assert detail.json()["selected_level"] == "STANDARD"
    assert hidden.status_code == 404

    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None
    # Model a pre-Phase-11 row, for which no authenticity signature existed.
    record.signatures.clear()
    record.signature_required = False
    record.selection_mode = None
    record.sensitivity = None
    record.document_category = None
    record.recommended_security_level = None
    record.policy_version = None
    record.decision_reasons = None
    record.policy_rules = None
    record.user_override = None
    db_session.commit()

    historical_download = client.get(
        f"/api/files/{uploaded['id']}/download", headers=owner_headers
    )
    historical_detail = client.get(
        f"/api/files/{uploaded['id']}/security-decision", headers=owner_headers
    )
    assert historical_download.status_code == 200
    assert historical_download.content == content
    assert historical_detail.status_code == 409


def test_adaptive_high_share_reuses_object_and_mlkem1024(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    alice, alice_headers = register_and_login(client, "adaptive-alice@example.com")
    bob, bob_headers = register_and_login(client, "adaptive-bob@example.com")
    content = b"adaptive high sharing"
    uploaded = adaptive_upload(
        client,
        alice_headers,
        filename="medical.txt",
        content=content,
        mode="AUTO",
        sensitivity="PUBLIC",
        category="MEDICAL",
    ).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None
    before = storage_service.resolve_path(record.storage_path).read_bytes()

    shared = client.post(
        f"/api/files/{uploaded['id']}/share",
        headers=alice_headers,
        json={"recipient_id": bob["id"]},
    )

    assert shared.status_code == 201, shared.text
    assert shared.json()["kem_algorithm"] == "ML-KEM-1024"
    assert storage_service.resolve_path(record.storage_path).read_bytes() == before
    assert db_session.scalar(select(func.count()).select_from(FileShare)) == 1
    assert db_session.scalar(select(func.count()).select_from(ShareCryptoMetadata)) == 1
    downloaded = client.get(
        f"/api/shares/{shared.json()['id']}/download", headers=bob_headers
    )
    assert downloaded.status_code == 200 and downloaded.content == content
    assert shared.json()["sender"]["id"] == alice["id"]
