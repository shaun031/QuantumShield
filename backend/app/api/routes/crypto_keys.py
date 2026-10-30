"""Multi-ML-KEM public metadata and idempotent keyset provisioning."""

from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import CurrentActiveUser, get_crypto_key_service
from app.core.config import settings
from app.crypto.security_levels import SecurityLevel, SecurityLevelPolicy
from app.schemas.crypto_key import CryptoKeyResponse, KEMAlgorithmResponse
from app.services.crypto_keys import (
    CryptoKeyAlreadyExistsError,
    CryptoKeyNotFoundError,
    CryptoKeyService,
)


router = APIRouter(prefix="/crypto", tags=["cryptography"])
KEMAlgorithm = Literal["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519"]


@router.get(
    "/algorithms",
    response_model=list[KEMAlgorithmResponse],
    summary="List supported explicit security levels",
)
def list_kem_algorithms(current_user: CurrentActiveUser) -> list[KEMAlgorithmResponse]:
    del current_user
    policy = SecurityLevelPolicy(SecurityLevel(settings.default_security_level))
    return [KEMAlgorithmResponse.model_validate(choice, from_attributes=True) for choice in policy.get_supported_levels()]


@router.post(
    "/keys/ensure",
    response_model=list[CryptoKeyResponse],
    summary="Idempotently provision all missing ML-KEM keys",
)
def ensure_crypto_keys(
    current_user: CurrentActiveUser,
    service: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
) -> list[CryptoKeyResponse]:
    try:
        keys = service.ensure_keyset_for_user(current_user)
    except CryptoKeyAlreadyExistsError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Concurrent ML-KEM key provisioning conflict; retry safely",
        ) from exc
    return [CryptoKeyResponse.model_validate(key) for key in keys]


@router.post(
    "/keys",
    response_model=list[CryptoKeyResponse],
    summary="Compatibility alias for idempotent ML-KEM keyset provisioning",
)
def create_crypto_keys(
    current_user: CurrentActiveUser,
    service: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
) -> list[CryptoKeyResponse]:
    return ensure_crypto_keys(current_user, service)


@router.get(
    "/keys/me",
    response_model=list[CryptoKeyResponse],
    summary="List the current user's active ML-KEM public-key metadata",
)
def get_my_crypto_keys(
    current_user: CurrentActiveUser,
    service: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
) -> list[CryptoKeyResponse]:
    keys = service.list_active_for_user(current_user.id)
    if not keys:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active ML-KEM keys are configured",
        )
    return [CryptoKeyResponse.model_validate(key) for key in keys]


@router.get(
    "/public-key/{user_id}",
    response_model=CryptoKeyResponse,
    summary="Get a known user's exact requested active ML-KEM key",
)
def get_public_crypto_key(
    user_id: UUID,
    current_user: CurrentActiveUser,
    service: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
    algorithm: Annotated[KEMAlgorithm, Query()] = "ML-KEM-768",
) -> CryptoKeyResponse:
    del current_user
    try:
        key = service.get_public_key(user_id, algorithm)
    except CryptoKeyNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Active {algorithm} public key not found",
        ) from exc
    return CryptoKeyResponse.model_validate(key)


@router.get("/signing-key/{user_id}", response_model=CryptoKeyResponse,
            summary="Get a user's active ML-DSA public signing key")
def get_public_signing_key(
    user_id: UUID,
    current_user: CurrentActiveUser,
    service: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
) -> CryptoKeyResponse:
    del current_user
    try:
        key = service.get_public_key(user_id, settings.default_signature_algorithm)
    except CryptoKeyNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Active signing key not found") from exc
    return CryptoKeyResponse.model_validate(key)
