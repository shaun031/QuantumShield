"""Authenticated owner-only file endpoints."""

from typing import Annotated
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import Response

from app.api.dependencies import CurrentActiveUser, get_file_service, get_share_service
from app.schemas.file import FileResponse
from app.schemas.security_policy import PolicyRuleResponse, SecurityDecisionResponse
from app.schemas.share import ShareCreate, ShareResponse
from app.schemas.signature import SignatureVerificationResponse
from app.crypto.security_levels import SecurityLevel
from app.crypto.suites import SecurityArchitecture
from app.services.security_policy import (
    DocumentCategory,
    PolicyValidationError,
    SelectionMode,
    Sensitivity,
)
from app.services.files import (
    FileIntegrityError,
    FileNotAccessibleError,
    FileService,
    CryptoSetupRequiredError,
    InvalidUploadError,
    LegacyFileRequiresMigrationError,
    UploadTooLargeError,
)
from app.services.shares import (
    DuplicateShareError,
    RecipientCryptoKeyRequiredError,
    RecipientNotFoundError,
    SelfShareError,
    ShareService,
)
from app.services.signatures import SignatureIntegrityError, SigningKeyRequiredError


router = APIRouter(prefix="/files", tags=["files"])


def inaccessible_file_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="File not found",
    )


@router.post(
    "/upload",
    response_model=FileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Encrypt and upload one file for the current user",
)
async def upload_file(
    current_user: CurrentActiveUser,
    file_service: Annotated[FileService, Depends(get_file_service)],
    file: Annotated[UploadFile, File(description="File bytes encrypted with AES-256-GCM")],
    selection_mode: Annotated[SelectionMode, Form()] = SelectionMode.MANUAL,
    security_level: Annotated[SecurityLevel | None, Form()] = None,
    sensitivity: Annotated[Sensitivity | None, Form()] = None,
    document_category: Annotated[DocumentCategory | None, Form()] = None,
    security_architecture: Annotated[SecurityArchitecture, Form()] = SecurityArchitecture.PQ_ONLY,
) -> FileResponse:
    try:
        selected_level = security_level
        if selection_mode is SelectionMode.MANUAL and selected_level is None:
            # Preserve the Phase 7 request contract for clients that omit the field.
            selected_level = SecurityLevel.STANDARD
        file_record = await file_service.upload_file(
            current_user,
            file,
            selected_level,
            selection_mode=selection_mode,
            sensitivity=sensitivity,
            document_category=document_category,
            security_architecture=security_architecture,
        )
    except PolicyValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc
    except InvalidUploadError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    except UploadTooLargeError as exc:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail="File exceeds the configured upload-size limit",
        ) from exc
    except (CryptoSetupRequiredError, SigningKeyRequiredError) as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Required cryptographic key setup is incomplete before uploading",
        ) from exc
    return FileResponse.model_validate(file_record)


@router.get(
    "/{file_id}/security-decision",
    response_model=SecurityDecisionResponse,
    summary="Get the owner's stored adaptive security decision",
)
def get_file_security_decision(
    file_id: UUID,
    current_user: CurrentActiveUser,
    file_service: Annotated[FileService, Depends(get_file_service)],
) -> SecurityDecisionResponse:
    try:
        file_record = file_service.get_file(current_user, file_id)
    except FileNotAccessibleError as exc:
        raise inaccessible_file_error() from exc
    if (
        file_record.selection_mode is None
        or file_record.recommended_security_level is None
        or file_record.security_level is None
        or file_record.kem_algorithm is None
        or file_record.policy_version is None
        or file_record.decision_reasons is None
        or file_record.policy_rules is None
        or file_record.user_override is None
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This historical file has no recorded Phase 8 policy decision",
        )
    return SecurityDecisionResponse(
        selection_mode=SelectionMode(file_record.selection_mode),
        minimum_required_level=SecurityLevel(file_record.recommended_security_level),
        recommended_level=SecurityLevel(file_record.recommended_security_level),
        selected_level=SecurityLevel(file_record.security_level),
        kem_algorithm=file_record.kem_algorithm,
        crypto_suite_id=file_record.crypto_suite_id,
        policy_version=file_record.policy_version,
        reasons=file_record.decision_reasons,
        rules_triggered=[PolicyRuleResponse.model_validate(rule) for rule in file_record.policy_rules],
        user_override=file_record.user_override,
        security_architecture=SecurityArchitecture(file_record.security_architecture),
    )


@router.get("", response_model=list[FileResponse], summary="List current user's files")
def list_files(
    current_user: CurrentActiveUser,
    file_service: Annotated[FileService, Depends(get_file_service)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[FileResponse]:
    return [
        FileResponse.model_validate(file_record)
        for file_record in file_service.list_files(
            current_user,
            limit=limit,
            offset=offset,
        )
    ]


@router.get("/{file_id}", response_model=FileResponse, summary="Get owned file metadata")
def get_file_metadata(
    file_id: UUID,
    current_user: CurrentActiveUser,
    file_service: Annotated[FileService, Depends(get_file_service)],
) -> FileResponse:
    try:
        file_record = file_service.get_file(current_user, file_id)
    except FileNotAccessibleError as exc:
        raise inaccessible_file_error() from exc
    return FileResponse.model_validate(file_record)


@router.post(
    "/{file_id}/share",
    response_model=ShareResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Wrap an owned file key for one recipient",
)
def share_file(
    file_id: UUID,
    payload: ShareCreate,
    current_user: CurrentActiveUser,
    service: Annotated[ShareService, Depends(get_share_service)],
) -> ShareResponse:
    try:
        share = service.create_share(current_user, file_id, payload.recipient_id)
    except FileNotAccessibleError as exc:
        raise inaccessible_file_error() from exc
    except SelfShareError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A file cannot be shared with its owner",
        ) from exc
    except RecipientNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recipient not found",
        ) from exc
    except RecipientCryptoKeyRequiredError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Recipient does not have an active {exc.algorithm} key",
        ) from exc
    except SigningKeyRequiredError as exc:
        raise HTTPException(status_code=409, detail="Sender signing key setup is incomplete") from exc
    except DuplicateShareError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This file is already shared with that recipient",
        ) from exc
    except SignatureIntegrityError as exc:
        raise HTTPException(status_code=422, detail="Signature verification failed") from exc
    except (LegacyFileRequiresMigrationError, FileIntegrityError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="The file key could not be prepared for sharing",
        ) from exc
    return ShareResponse.model_validate(share)


@router.get("/{file_id}/verify", response_model=SignatureVerificationResponse,
            summary="Verify an owned file's sender authenticity and ciphertext")
def verify_file(
    file_id: UUID,
    current_user: CurrentActiveUser,
    file_service: Annotated[FileService, Depends(get_file_service)],
) -> SignatureVerificationResponse:
    try:
        result = file_service.verify_file(current_user, file_id)
    except FileNotAccessibleError as exc:
        raise inaccessible_file_error() from exc
    except FileIntegrityError as exc:
        raise HTTPException(status_code=422, detail="File integrity verification failed") from exc
    return SignatureVerificationResponse.from_result(result)


@router.get(
    "/{file_id}/download",
    response_class=Response,
    summary="Decrypt and download an owned file",
)
def download_file(
    file_id: UUID,
    current_user: CurrentActiveUser,
    file_service: Annotated[FileService, Depends(get_file_service)],
) -> Response:
    try:
        file_record, plaintext = file_service.get_download(current_user, file_id)
    except FileNotAccessibleError as exc:
        raise inaccessible_file_error() from exc
    except LegacyFileRequiresMigrationError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Legacy plaintext file requires encryption migration",
        ) from exc
    except SignatureIntegrityError as exc:
        raise HTTPException(status_code=422, detail="Signature verification failed") from exc
    except FileIntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="File integrity verification failed",
        ) from exc
    encoded_filename = quote(file_record.original_filename, safe="")
    return Response(
        content=plaintext,
        media_type=file_record.mime_type,
        headers={
            "Content-Disposition": (
                f"attachment; filename*=UTF-8''{encoded_filename}"
            )
        },
    )


@router.delete(
    "/{file_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an owned file",
)
def delete_file(
    file_id: UUID,
    current_user: CurrentActiveUser,
    file_service: Annotated[FileService, Depends(get_file_service)],
) -> None:
    try:
        file_service.delete_file(current_user, file_id)
    except FileNotAccessibleError as exc:
        raise inaccessible_file_error() from exc
    except FileIntegrityError as exc:
        raise HTTPException(status_code=422, detail="File integrity verification failed") from exc
