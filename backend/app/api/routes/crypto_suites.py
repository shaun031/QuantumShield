"""Authenticated discovery of allow-listed crypto suites."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import CurrentActiveUser, get_crypto_suite_registry
from app.crypto.suites import CryptoSuiteRegistry
from app.schemas.crypto_suite import CryptoSuiteResponse


router = APIRouter(prefix="/crypto/suites", tags=["crypto suites"])


@router.get("", response_model=list[CryptoSuiteResponse])
def list_crypto_suites(
    current_user: CurrentActiveUser,
    registry: Annotated[CryptoSuiteRegistry, Depends(get_crypto_suite_registry)],
) -> list[CryptoSuiteResponse]:
    del current_user
    return [
        CryptoSuiteResponse(
            suite_id=suite.suite_id,
            version=suite.version,
            security_level=suite.security_level,
            status=suite.status,
            content_aead=suite.content_algorithm,
            kem=suite.kem_algorithm,
            kdf=suite.kdf_algorithm,
            key_wrap=suite.key_wrap_algorithm,
            description=suite.description,
            available=True,
            architecture=suite.architecture,
            classical_algorithm=suite.classical_algorithm,
        )
        for suite in registry.get_supported_suites()
    ]
