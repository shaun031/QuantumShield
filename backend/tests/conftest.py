"""Test-only environment defaults loaded before application imports."""

import base64
import os
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

# Unit tests replace the database dependency and never perform schema work.
# A built-in in-memory URL keeps configuration self-contained without adding a
# test database password or requiring the developer's PostgreSQL service.
os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault(
    "SECRET_KEY",
    "test-only-secret-key-that-is-longer-than-thirty-two-bytes",
)
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DEBUG", "false")
os.environ.setdefault("MAX_UPLOAD_SIZE_MB", "1")
os.environ.setdefault(
    "MASTER_KEY_BASE64",
    base64.urlsafe_b64encode(b"T" * 32).decode("ascii"),
)


from app.db.base import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402
from app.api.dependencies import get_storage_service  # noqa: E402
from app.storage.local import LocalStorageService  # noqa: E402
import app.models  # noqa: E402, F401
from app.main import app as application  # noqa: E402


test_engine = create_engine(
    "sqlite+pysqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(
    bind=test_engine,
    class_=Session,
    autoflush=False,
    expire_on_commit=False,
)


@pytest.fixture(autouse=True)
def reset_test_database() -> Generator[None, None, None]:
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)
    yield
    application.dependency_overrides.clear()


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    with TestingSessionLocal() as session:
        yield session


@pytest.fixture
def storage_service(tmp_path: Path) -> LocalStorageService:
    return LocalStorageService(tmp_path / "stored-files")


@pytest.fixture
def client(
    storage_service: LocalStorageService,
) -> Generator[TestClient, None, None]:
    def override_get_db() -> Generator[Session, None, None]:
        with TestingSessionLocal() as session:
            yield session

    application.dependency_overrides[get_db] = override_get_db
    application.dependency_overrides[get_storage_service] = lambda: storage_service
    with TestClient(application, raise_server_exceptions=False) as test_client:
        yield test_client
