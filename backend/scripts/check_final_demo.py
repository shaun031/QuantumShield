"""Disposable, API-level Phase 17 rehearsal; never touches a configured database."""

import base64
import hashlib
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory


BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

# Set these before importing the application, overriding even a developer .env.
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = "sqlite+pysqlite:///:memory:"
os.environ["SECRET_KEY"] = "phase-17-disposable-test-secret-longer-than-32-bytes"
os.environ["MASTER_KEY_BASE64"] = base64.urlsafe_b64encode(b"D" * 32).decode("ascii")

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

from app.api.dependencies import get_storage_service  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.main import app as application  # noqa: E402
from app.storage.local import LocalStorageService  # noqa: E402
import app.models  # noqa: E402, F401


def require(response, expected: int, step: str):
    if response.status_code != expected:
        raise RuntimeError(f"{step}: expected HTTP {expected}, got {response.status_code}")
    return response


def register(client: TestClient, email: str) -> tuple[dict, dict[str, str]]:
    password = "Disposable-Demo-Password-123!"
    user = require(client.post("/api/auth/register", json={
        "name": email.split("@", 1)[0], "email": email, "password": password,
    }), 201, "register").json()
    token = require(client.post("/api/auth/login", json={
        "email": email, "password": password,
    }), 200, "login").json()["access_token"]
    return user, {"Authorization": f"Bearer {token}"}


def main() -> None:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    sessions = sessionmaker(bind=engine, class_=Session, expire_on_commit=False)
    Base.metadata.create_all(engine)

    def override_db():
        with sessions() as session:
            yield session

    with TemporaryDirectory(prefix="quantumshield-phase17-") as directory:
        application.dependency_overrides[get_db] = override_db
        application.dependency_overrides[get_storage_service] = lambda: LocalStorageService(
            Path(directory) / "objects"
        )
        try:
            with TestClient(application, raise_server_exceptions=False) as client:
                require(client.get("/api/health"), 200, "health")
                alice, alice_headers = register(client, "phase17-alice@example.com")
                bob, bob_headers = register(client, "phase17-bob@example.com")
                source = b"QuantumShield disposable final demo\n"
                original_sha256 = hashlib.sha256(source).hexdigest()
                item = require(client.post(
                    "/api/files/upload", headers=alice_headers,
                    data={"selection_mode": "AUTO", "sensitivity": "CONFIDENTIAL",
                          "security_architecture": "HYBRID"},
                    files={"file": ("final-demo.txt", source, "text/plain")},
                ), 201, "AUTO/HYBRID upload").json()
                if item["selection_mode"] != "AUTO" or item["security_architecture"] != "HYBRID":
                    raise RuntimeError("Effective mode/architecture mismatch")
                if item["security_level"] != "HIGH" or item["crypto_suite_id"] != "QS-HYBRID-1024-V1":
                    raise RuntimeError("Confidential policy did not select expected HIGH hybrid suite")
                file_id = item["id"]
                if require(client.get(f"/api/files/{file_id}/verify", headers=alice_headers),
                           200, "file verification").json()["status"] != "VALID":
                    raise RuntimeError("File signature not valid")
                share = require(client.post(
                    f"/api/files/{file_id}/share", headers=alice_headers,
                    json={"recipient_id": bob["id"]},
                ), 201, "share").json()
                share_id = share["id"]
                if require(client.get(f"/api/shares/{share_id}/verify", headers=bob_headers),
                           200, "share verification").json()["status"] != "VALID":
                    raise RuntimeError("Share signature not valid")
                downloaded = require(client.get(
                    f"/api/shares/{share_id}/download", headers=bob_headers,
                ), 200, "recipient download").content
                if hashlib.sha256(downloaded).hexdigest() != original_sha256:
                    raise RuntimeError("Downloaded SHA-256 mismatch")
                require(client.get(f"/api/files/{file_id}/download", headers=bob_headers),
                        404, "non-owner file access denied")
                summary = require(client.get("/api/dashboard/summary", headers=alice_headers),
                                  200, "dashboard summary").json()
                if summary["my_files"] != 1 or summary["active_shares"] != 1:
                    raise RuntimeError("Dashboard counts mismatch")
                require(client.get("/api/research/benchmarks/latest", headers=alice_headers),
                        200, "benchmark result view")
                require(client.get("/api/research/adaptive/latest", headers=alice_headers),
                        200, "adaptive result view")
                require(client.post(f"/api/shares/{share_id}/revoke", headers=alice_headers),
                        200, "revoke")
                require(client.get(f"/api/shares/{share_id}/download", headers=bob_headers),
                        403, "revoked access denied")
                print("PASS: Alice/Bob AUTO-HYBRID upload, signatures, SHA-256 download, dashboard, research exports, and revocation")
                print("Scope: disposable in-memory SQLite API rehearsal; not a live-browser or PostgreSQL test")
        finally:
            application.dependency_overrides.clear()
            engine.dispose()


if __name__ == "__main__":
    main()
