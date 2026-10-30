"""Authenticated sent/received share metadata and recipient download endpoints."""

from typing import Annotated
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import Response

from app.api.dependencies import CurrentActiveUser, get_share_service
from app.models.file_share import FileShare
from app.schemas.share import ShareResponse, ShareRevokeRequest
from app.schemas.signature import SignatureVerificationResponse
from app.services.signatures import SignatureIntegrityError
from app.services.shares import (
    ShareIntegrityError,
    ShareNotAccessibleError,
    ShareRevokedError,
    ShareService,
)


router = APIRouter(prefix="/shares", tags=["shares"])


def inaccessible_share_error() -> HTTPException:
    return HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share not found")


def share_response_for_viewer(share: FileShare, viewer_id: UUID) -> ShareResponse:
    response = ShareResponse.model_validate(share)
    if share.sender_id != viewer_id:
        response.revoke_reason = None
    return response


@router.get("/received", response_model=list[ShareResponse], summary="List files shared with me")
def list_received_shares(
    current_user: CurrentActiveUser,
    service: Annotated[ShareService, Depends(get_share_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ShareResponse]:
    return [
        share_response_for_viewer(share, current_user.id)
        for share in service.list_received(current_user, limit=limit, offset=offset)
    ]


@router.get("/sent", response_model=list[ShareResponse], summary="List files I shared")
def list_sent_shares(
    current_user: CurrentActiveUser,
    service: Annotated[ShareService, Depends(get_share_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[ShareResponse]:
    return [
        ShareResponse.model_validate(share)
        for share in service.list_sent(current_user, limit=limit, offset=offset)
    ]


@router.get("/{share_id}", response_model=ShareResponse, summary="Get authorized share metadata")
def get_share(
    share_id: UUID,
    current_user: CurrentActiveUser,
    service: Annotated[ShareService, Depends(get_share_service)],
) -> ShareResponse:
    try:
        return share_response_for_viewer(service.get_share(current_user, share_id), current_user.id)
    except ShareNotAccessibleError as exc:
        raise inaccessible_share_error() from exc


@router.post("/{share_id}/revoke", response_model=ShareResponse,
             summary="Revoke one recipient's future access as the file owner")
def revoke_share(
    share_id: UUID,
    current_user: CurrentActiveUser,
    service: Annotated[ShareService, Depends(get_share_service)],
    payload: ShareRevokeRequest | None = None,
) -> ShareResponse:
    try:
        share = service.revoke_share(current_user, share_id, payload.reason if payload else None)
    except ShareNotAccessibleError as exc:
        raise inaccessible_share_error() from exc
    except ShareIntegrityError as exc:
        raise HTTPException(status_code=422, detail="Share lifecycle update failed") from exc
    return ShareResponse.model_validate(share)


@router.get("/{share_id}/verify", response_model=SignatureVerificationResponse,
            summary="Verify a visible share's sender authenticity and ciphertext")
def verify_share(
    share_id: UUID,
    current_user: CurrentActiveUser,
    service: Annotated[ShareService, Depends(get_share_service)],
) -> SignatureVerificationResponse:
    try:
        result = service.verify_share(current_user, share_id)
    except ShareNotAccessibleError as exc:
        raise inaccessible_share_error() from exc
    except ShareIntegrityError as exc:
        raise HTTPException(status_code=422, detail="Shared file integrity verification failed") from exc
    return SignatureVerificationResponse.from_result(result)


@router.get(
    "/{share_id}/download",
    response_class=Response,
    summary="Decrypt a shared file as its intended recipient",
)
def download_shared_file(
    share_id: UUID,
    current_user: CurrentActiveUser,
    service: Annotated[ShareService, Depends(get_share_service)],
) -> Response:
    try:
        share, plaintext = service.get_download(current_user, share_id)
    except ShareNotAccessibleError as exc:
        raise inaccessible_share_error() from exc
    except ShareRevokedError as exc:
        raise HTTPException(status_code=403,
                            detail="Access to this shared file has been revoked.") from exc
    except SignatureIntegrityError as exc:
        raise HTTPException(status_code=422, detail="Signature verification failed") from exc
    except ShareIntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Shared file integrity verification failed",
        ) from exc
    encoded_filename = quote(share.file.original_filename, safe="")
    return Response(
        content=plaintext,
        media_type=share.file.mime_type,
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"},
    )
