"""Safe Phase 8 policy input, option, and decision schemas."""

from pydantic import BaseModel, Field, field_validator

from app.crypto.security_levels import SecurityLevel
from app.crypto.suites import SecurityArchitecture
from app.services.security_policy import (
    DocumentCategory,
    SelectionMode,
    Sensitivity,
)


class SecurityRecommendationRequest(BaseModel):
    file_name: str = Field(min_length=1, max_length=255)
    file_size: int = Field(ge=0)
    mime_type: str = Field(default="application/octet-stream", max_length=255)
    sensitivity: Sensitivity | None = None
    document_category: DocumentCategory | None = None
    security_architecture: SecurityArchitecture = SecurityArchitecture.PQ_ONLY

    @field_validator("file_name")
    @classmethod
    def validate_file_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("file_name cannot be blank")
        return normalized


class PolicyRuleResponse(BaseModel):
    rule: str
    required_level: SecurityLevel
    message: str


class SecurityDecisionResponse(BaseModel):
    selection_mode: SelectionMode
    minimum_required_level: SecurityLevel
    recommended_level: SecurityLevel
    selected_level: SecurityLevel
    kem_algorithm: str
    crypto_suite_id: str
    policy_version: str
    reasons: list[str]
    rules_triggered: list[PolicyRuleResponse]
    user_override: bool
    security_architecture: SecurityArchitecture = SecurityArchitecture.PQ_ONLY


class SecurityLevelOptionResponse(BaseModel):
    security_level: SecurityLevel
    algorithm: str
    suite_id: str
    description: str
    rank: int
    is_default: bool


class SecurityOptionsResponse(BaseModel):
    selection_modes: list[SelectionMode]
    sensitivities: list[Sensitivity]
    document_categories: list[DocumentCategory]
    security_levels: list[SecurityLevelOptionResponse]
    policy_version: str
    security_architectures: list[SecurityArchitecture] = [SecurityArchitecture.PQ_ONLY, SecurityArchitecture.HYBRID]
