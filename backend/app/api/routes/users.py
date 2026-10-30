"""Authenticated user endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import CurrentActiveUser
from app.crypto.kem.registry import SUPPORTED_KEM_ALGORITHMS
from app.core.config import settings
from app.db.session import get_db
from app.repositories.crypto_key import CryptoKeyRepository
from app.repositories.user import UserRepository
from app.schemas.user import UserResponse, UserSearchResponse


router = APIRouter(prefix="/users", tags=["users"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Return the authenticated user's profile",
)
def read_current_user(current_user: CurrentActiveUser) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.get(
    "/search",
    response_model=list[UserSearchResponse],
    summary="Search active users eligible to receive a share",
)
def search_users(
    current_user: CurrentActiveUser,
    database: Annotated[Session, Depends(get_db)],
    q: Annotated[str, Query(min_length=3, max_length=100)],
    limit: Annotated[int, Query(ge=1, le=20)] = 10,
) -> list[UserSearchResponse]:
    query = q.strip()
    if len(query) < 3:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Search query must contain at least 3 non-space characters",
        )
    users = UserRepository(database).search_active(
        query,
        exclude_user_id=current_user.id,
        limit=limit,
    )
    key_repository = CryptoKeyRepository(database)
    results = []
    required = SUPPORTED_KEM_ALGORITHMS
    for user in users:
        configured = [
            algorithm
            for algorithm in required
            if key_repository.get_active(user.id, algorithm) is not None
        ]
        ready = configured + [
            algorithm for algorithm in ("X25519", settings.default_signature_algorithm)
            if key_repository.get_active(user.id, algorithm) is not None
        ]
        results.append(
            UserSearchResponse(
                id=user.id,
                name=user.name,
                email=user.email,
                crypto_ready=len(configured) == len(required),
                supported_kem_algorithms=configured,
                supported_key_algorithms=ready,
            )
        )
    return results

