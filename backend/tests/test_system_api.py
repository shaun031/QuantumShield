"""API tests that do not require a running PostgreSQL server."""

from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from app.db.session import get_db
from app.main import app


def test_health_returns_process_liveness(client: TestClient) -> None:
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_system_status_reports_available_database(client: TestClient) -> None:
    response = client.get("/api/system/status")

    assert response.status_code == 200
    assert response.json() == {
        "backend": "ok",
        "database": "ok",
        "supported_kems": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "supported_suites": ["QS-PQ-512-V1", "QS-PQ-768-V1", "QS-PQ-1024-V1", "QS-HYBRID-512-V1", "QS-HYBRID-768-V1", "QS-HYBRID-1024-V1"],
        "provider_availability": {
            "aead": ["AES-256-GCM"],
            "kem": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "key_agreement": ["X25519"],
            "kdf": ["HKDF-SHA256"],
            "key_wrap": ["KEK-AES-256-GCM"],
        },
        "active_suite_count": 6,
    }


def test_system_status_hides_database_failure_details(client: TestClient) -> None:
    class UnavailableDatabase:
        def execute(self, _statement: object) -> object:
            raise SQLAlchemyError("sensitive driver details")

    def override_get_db():
        yield UnavailableDatabase()

    app.dependency_overrides[get_db] = override_get_db

    response = client.get("/api/system/status")

    assert response.status_code == 503
    assert response.json() == {
        "backend": "ok",
        "database": "unavailable",
        "supported_kems": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
        "supported_suites": ["QS-PQ-512-V1", "QS-PQ-768-V1", "QS-PQ-1024-V1", "QS-HYBRID-512-V1", "QS-HYBRID-768-V1", "QS-HYBRID-1024-V1"],
        "provider_availability": {
            "aead": ["AES-256-GCM"],
            "kem": ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            "key_agreement": ["X25519"],
            "kdf": ["HKDF-SHA256"],
            "key_wrap": ["KEK-AES-256-GCM"],
        },
        "active_suite_count": 6,
    }
    assert "sensitive driver details" not in response.text


def test_cors_allows_configured_local_frontend(client: TestClient) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_cors_does_not_allow_unknown_origin(client: TestClient) -> None:
    response = client.options(
        "/api/health",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert "access-control-allow-origin" not in response.headers

