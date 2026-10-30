"""Authenticated explainable security-policy endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import CurrentActiveUser, get_crypto_suite_registry, get_security_policy_engine
from app.core.config import settings
from app.crypto.security_levels import SECURITY_LEVEL_RANK, SecurityLevel, SecurityLevelPolicy
from app.schemas.security_policy import (
    PolicyRuleResponse,
    SecurityDecisionResponse,
    SecurityLevelOptionResponse,
    SecurityOptionsResponse,
    SecurityRecommendationRequest,
)
from app.services.security_policy import (
    POLICY_VERSION,
    DocumentCategory,
    SecurityAssessmentInput,
    SecurityDecision,
    SecurityPolicyEngine,
    SelectionMode,
    Sensitivity,
)
from app.crypto.suites import CryptoSuiteRegistry, SecurityArchitecture


router = APIRouter(prefix="/security", tags=["security policy"])


def decision_response(decision: SecurityDecision) -> SecurityDecisionResponse:
    return SecurityDecisionResponse(
        selection_mode=decision.selection_mode,
        minimum_required_level=decision.minimum_required_level,
        recommended_level=decision.recommended_level,
        selected_level=decision.selected_level,
        kem_algorithm=decision.kem_algorithm,
        crypto_suite_id=decision.crypto_suite_id,
        policy_version=decision.policy_version,
        reasons=list(decision.reasons),
        rules_triggered=[
            PolicyRuleResponse(
                rule=result.rule,
                required_level=result.required_level,
                message=result.message,
            )
            for result in decision.rules_triggered
        ],
        user_override=decision.user_override,
        security_architecture=decision.security_architecture,
    )


@router.get("/options", response_model=SecurityOptionsResponse)
def get_security_options(
    current_user: CurrentActiveUser,
    registry: Annotated[CryptoSuiteRegistry, Depends(get_crypto_suite_registry)],
) -> SecurityOptionsResponse:
    del current_user
    level_policy = SecurityLevelPolicy(
        SecurityLevel(settings.default_security_level), suite_registry=registry
    )
    return SecurityOptionsResponse(
        selection_modes=list(SelectionMode),
        sensitivities=list(Sensitivity),
        document_categories=list(DocumentCategory),
        security_levels=[
            SecurityLevelOptionResponse(
                security_level=choice.security_level,
                algorithm=choice.algorithm,
                suite_id=choice.suite_id,
                description=choice.description,
                rank=int(SECURITY_LEVEL_RANK[choice.security_level]),
                is_default=choice.is_default,
            )
            for choice in level_policy.get_supported_levels()
        ],
        policy_version=POLICY_VERSION,
        security_architectures=list(SecurityArchitecture),
    )


@router.post("/recommend", response_model=SecurityDecisionResponse)
def recommend_security(
    payload: SecurityRecommendationRequest,
    current_user: CurrentActiveUser,
    engine: Annotated[SecurityPolicyEngine, Depends(get_security_policy_engine)],
) -> SecurityDecisionResponse:
    del current_user
    decision = engine.recommend_level(
        SecurityAssessmentInput(
            file_name=payload.file_name,
            file_size=payload.file_size,
            mime_type=payload.mime_type,
            sensitivity=payload.sensitivity,
            document_category=payload.document_category,
        ),
        payload.security_architecture,
    )
    return decision_response(decision)
