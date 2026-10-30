"""Safe file metadata response schemas."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class FileResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    original_filename: str
    file_size: int
    mime_type: str
    sha256: str
    signature_required: bool
    is_encrypted: bool
    encryption_algorithm: str | None
    post_quantum_protected: bool
    kem_algorithm: str | None
    security_level: str | None
    selection_mode: str | None
    sensitivity: str | None
    document_category: str | None
    recommended_security_level: str | None
    policy_version: str | None
    decision_reasons: list[str] | None
    user_override: bool | None
    crypto_version: int | None
    crypto_suite_id: str | None
    crypto_suite_version: int | None
    security_architecture: str | None
    classical_algorithm: str | None
    created_at: datetime
    updated_at: datetime
