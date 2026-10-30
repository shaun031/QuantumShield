"""Process liveness and infrastructure readiness routes."""

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.db.init_db import is_database_available
from app.db.session import get_db
from app.schemas.system import HealthResponse, SystemStatusResponse
from app.crypto.kem.registry import SUPPORTED_KEM_ALGORITHMS
from app.crypto.suite_specs import APPROVED_SUITE_SPECS


router = APIRouter(tags=["system"])


def crypto_capabilities() -> dict[str, list[str]]:
    return {
        "aead": list(dict.fromkeys(spec.content_aead for spec in APPROVED_SUITE_SPECS)),
        "kem": list(SUPPORTED_KEM_ALGORITHMS),
        "key_agreement": ["X25519"],
        "kdf": list(dict.fromkeys(spec.kdf for spec in APPROVED_SUITE_SPECS)),
        "key_wrap": list(dict.fromkeys(spec.key_wrap for spec in APPROVED_SUITE_SPECS)),
    }


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Check backend process liveness",
)
def health() -> HealthResponse:
    return HealthResponse(status="ok")


@router.get(
    "/system/status",
    response_model=SystemStatusResponse,
    responses={
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": SystemStatusResponse,
            "description": "Backend is running but PostgreSQL is unavailable.",
        }
    },
    summary="Check backend and PostgreSQL status",
)
def system_status(
    response: Response,
    database: Session = Depends(get_db),
) -> SystemStatusResponse:
    if is_database_available(database):
        return SystemStatusResponse(
            backend="ok",
            database="ok",
            supported_kems=list(SUPPORTED_KEM_ALGORITHMS),
            supported_suites=[spec.suite_id for spec in APPROVED_SUITE_SPECS],
            provider_availability=crypto_capabilities(),
            active_suite_count=len(APPROVED_SUITE_SPECS),
        )

    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return SystemStatusResponse(
        backend="ok",
        database="unavailable",
        supported_kems=list(SUPPORTED_KEM_ALGORITHMS),
        supported_suites=[spec.suite_id for spec in APPROVED_SUITE_SPECS],
        provider_availability=crypto_capabilities(),
        active_suite_count=len(APPROVED_SUITE_SPECS),
    )

