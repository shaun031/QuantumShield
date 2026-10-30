"""Public sharing request and response schemas without key material."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class ShareCreate(BaseModel):
    recipient_id: UUID


class ShareRevokeRequest(BaseModel):
    reason: str | None = Field(default=None, max_length=255)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class ShareUserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    email: EmailStr


class SharedFileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    original_filename: str
    file_size: int
    mime_type: str
    sha256: str
    signature_required: bool
    security_level: str | None
    kem_algorithm: str | None
    crypto_suite_id: str | None
    security_architecture: str | None
    classical_algorithm: str | None


class ShareResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    file: SharedFileResponse
    sender: ShareUserResponse
    recipient: ShareUserResponse
    permission: str
    status: str
    revoked_at: datetime | None
    revoke_reason: str | None
    signature_required: bool
    kem_algorithm: str
    security_level: str
    crypto_suite_id: str
    security_architecture: str
    classical_algorithm: str | None
    created_at: datetime
