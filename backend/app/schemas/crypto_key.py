"""Public-only user cryptographic key response schemas."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CryptoKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    user_id: UUID
    algorithm: Literal["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "X25519", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]
    key_purpose: Literal["KEM", "KEY_AGREEMENT", "SIGNATURE"]
    key_version: int
    is_active: bool
    created_at: datetime
    public_key_available: bool = True
    public_key_base64: str


class KEMAlgorithmResponse(BaseModel):
    security_level: Literal["LOW", "STANDARD", "HIGH"]
    algorithm: Literal["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    description: str
    is_default: bool
