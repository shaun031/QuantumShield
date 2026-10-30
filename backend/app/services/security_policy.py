"""Deterministic, explainable Phase 8 metadata policy selection."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from app.crypto.security_levels import (
    SECURITY_LEVEL_RANK,
    SecurityLevel,
    SecurityLevelPolicy,
)
from app.crypto.suites import SecurityArchitecture


POLICY_VERSION = "adaptive-v1"


class SelectionMode(StrEnum):
    MANUAL = "MANUAL"
    RECOMMEND = "RECOMMEND"
    AUTO = "AUTO"


class Sensitivity(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    HIGHLY_CONFIDENTIAL = "HIGHLY_CONFIDENTIAL"


class DocumentCategory(StrEnum):
    GENERAL = "GENERAL"
    ACADEMIC = "ACADEMIC"
    PERSONAL = "PERSONAL"
    FINANCIAL = "FINANCIAL"
    LEGAL = "LEGAL"
    MEDICAL = "MEDICAL"
    SOURCE_CODE = "SOURCE_CODE"
    IDENTITY = "IDENTITY"
    CREDENTIALS = "CREDENTIALS"
    ARCHIVE = "ARCHIVE"
    OTHER = "OTHER"


# Project policy, not a universal legal or scientific classification.
SENSITIVITY_MINIMUM_LEVELS = {
    Sensitivity.PUBLIC: SecurityLevel.LOW,
    Sensitivity.INTERNAL: SecurityLevel.STANDARD,
    Sensitivity.CONFIDENTIAL: SecurityLevel.HIGH,
    Sensitivity.HIGHLY_CONFIDENTIAL: SecurityLevel.HIGH,
}

CATEGORY_MINIMUM_LEVELS = {
    DocumentCategory.GENERAL: SecurityLevel.LOW,
    DocumentCategory.ACADEMIC: SecurityLevel.LOW,
    DocumentCategory.PERSONAL: SecurityLevel.STANDARD,
    DocumentCategory.FINANCIAL: SecurityLevel.STANDARD,
    DocumentCategory.LEGAL: SecurityLevel.STANDARD,
    DocumentCategory.MEDICAL: SecurityLevel.HIGH,
    DocumentCategory.SOURCE_CODE: SecurityLevel.STANDARD,
    DocumentCategory.IDENTITY: SecurityLevel.HIGH,
    DocumentCategory.CREDENTIALS: SecurityLevel.HIGH,
    DocumentCategory.ARCHIVE: SecurityLevel.LOW,
    DocumentCategory.OTHER: SecurityLevel.LOW,
}

SECRET_FILE_EXTENSION_MINIMUMS = {
    ".env": SecurityLevel.HIGH,
    ".key": SecurityLevel.HIGH,
    ".pem": SecurityLevel.HIGH,
    ".p12": SecurityLevel.HIGH,
    ".pfx": SecurityLevel.HIGH,
}


class PolicyValidationError(ValueError):
    """Raised when a selection-mode combination is contradictory or unsafe."""


@dataclass(frozen=True)
class SecurityAssessmentInput:
    file_name: str
    file_size: int
    mime_type: str
    sensitivity: Sensitivity | None = None
    document_category: DocumentCategory | None = None

    def __post_init__(self) -> None:
        if not self.file_name.strip():
            raise PolicyValidationError("A file name is required for policy evaluation")
        if self.file_size < 0:
            raise PolicyValidationError("File size cannot be negative")


@dataclass(frozen=True)
class PolicyRuleResult:
    rule: str
    required_level: SecurityLevel
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "rule": self.rule,
            "required_level": self.required_level.value,
            "message": self.message,
        }


@dataclass(frozen=True)
class SecurityDecision:
    selected_level: SecurityLevel
    minimum_required_level: SecurityLevel
    recommended_level: SecurityLevel
    kem_algorithm: str
    crypto_suite_id: str
    selection_mode: SelectionMode
    reasons: tuple[str, ...]
    rules_triggered: tuple[PolicyRuleResult, ...]
    policy_version: str
    user_override: bool
    security_architecture: SecurityArchitecture = SecurityArchitecture.PQ_ONLY

    def stored_rules(self) -> list[dict[str, str]]:
        return [result.as_dict() for result in self.rules_triggered]


class PolicyRule(Protocol):
    def evaluate(
        self, assessment: SecurityAssessmentInput
    ) -> PolicyRuleResult | None: ...


class SensitivityRule:
    def evaluate(self, assessment: SecurityAssessmentInput) -> PolicyRuleResult | None:
        if assessment.sensitivity is None:
            return None
        level = SENSITIVITY_MINIMUM_LEVELS[assessment.sensitivity]
        return PolicyRuleResult(
            rule="sensitivity",
            required_level=level,
            message=(
                f"{assessment.sensitivity.value} sensitivity requires at least "
                f"{level.value} protection."
            ),
        )


class CategoryRule:
    def evaluate(self, assessment: SecurityAssessmentInput) -> PolicyRuleResult | None:
        if assessment.document_category is None:
            return None
        level = CATEGORY_MINIMUM_LEVELS[assessment.document_category]
        return PolicyRuleResult(
            rule="document_category",
            required_level=level,
            message=(
                f"{assessment.document_category.value} category requires at least "
                f"{level.value} protection under project policy."
            ),
        )


class SecretExtensionRule:
    def evaluate(self, assessment: SecurityAssessmentInput) -> PolicyRuleResult | None:
        extension = Path(assessment.file_name).suffix.lower()
        level = SECRET_FILE_EXTENSION_MINIMUMS.get(extension)
        if level is None:
            return None
        return PolicyRuleResult(
            rule="file_extension",
            required_level=level,
            message=(
                f"The {extension} extension is treated as secret-bearing and requires "
                f"{level.value} protection under project policy."
            ),
        )


class SecurityPolicyEngine:
    """Apply small independent rules and select their strongest requirement."""

    def __init__(
        self,
        rules: tuple[PolicyRule, ...] | None = None,
        level_policy: SecurityLevelPolicy | None = None,
    ) -> None:
        self.rules = rules or (
            SensitivityRule(),
            CategoryRule(),
            SecretExtensionRule(),
        )
        self.level_policy = level_policy or SecurityLevelPolicy()

    def _rule_results(
        self, assessment: SecurityAssessmentInput
    ) -> tuple[PolicyRuleResult, ...]:
        results = tuple(
            result
            for rule in self.rules
            if (result := rule.evaluate(assessment)) is not None
        )
        if results:
            return results
        return (
            PolicyRuleResult(
                rule="default",
                required_level=SecurityLevel.STANDARD,
                message=(
                    "No stronger policy signals were provided; STANDARD is the "
                    "default project policy."
                ),
            ),
        )

    @staticmethod
    def _strongest(results: tuple[PolicyRuleResult, ...]) -> SecurityLevel:
        return max(
            (result.required_level for result in results),
            key=lambda level: SECURITY_LEVEL_RANK[level],
        )

    def recommend_level(
        self, assessment: SecurityAssessmentInput, architecture: SecurityArchitecture = SecurityArchitecture.PQ_ONLY
    ) -> SecurityDecision:
        results = self._rule_results(assessment)
        recommended = self._strongest(results)
        reasons = tuple(result.message for result in results) + (
            f"The strongest applicable requirement is {recommended.value}.",
        )
        return SecurityDecision(
            selected_level=recommended,
            minimum_required_level=recommended,
            recommended_level=recommended,
            kem_algorithm=self.level_policy.get_algorithm(recommended),
            crypto_suite_id=self.level_policy.get_suite_id_for_architecture(recommended, architecture),
            selection_mode=SelectionMode.RECOMMEND,
            reasons=reasons,
            rules_triggered=results,
            policy_version=POLICY_VERSION,
            user_override=False,
            security_architecture=architecture,
        )

    def evaluate(
        self,
        assessment: SecurityAssessmentInput,
        selection_mode: SelectionMode,
        user_selected_level: SecurityLevel | None = None,
        architecture: SecurityArchitecture = SecurityArchitecture.PQ_ONLY,
    ) -> SecurityDecision:
        if selection_mode is SelectionMode.MANUAL:
            if user_selected_level is None:
                raise PolicyValidationError(
                    "MANUAL mode requires an explicit security level"
                )
            message = f"User manually selected {user_selected_level.value}."
            manual_result = PolicyRuleResult(
                rule="manual_selection",
                required_level=user_selected_level,
                message=message,
            )
            return SecurityDecision(
                selected_level=user_selected_level,
                minimum_required_level=user_selected_level,
                recommended_level=user_selected_level,
                kem_algorithm=self.level_policy.get_algorithm(user_selected_level),
                crypto_suite_id=self.level_policy.get_suite_id_for_architecture(user_selected_level, architecture),
                selection_mode=selection_mode,
                reasons=(message,),
                rules_triggered=(manual_result,),
                policy_version=POLICY_VERSION,
                user_override=False,
                security_architecture=architecture,
            )

        recommendation = self.recommend_level(assessment, architecture)
        if selection_mode is SelectionMode.AUTO:
            if user_selected_level is not None:
                raise PolicyValidationError(
                    "AUTO mode does not accept an explicit security level"
                )
            return replace(recommendation, selection_mode=SelectionMode.AUTO)

        if selection_mode is SelectionMode.RECOMMEND:
            if user_selected_level is None:
                raise PolicyValidationError(
                    "RECOMMEND mode requires a confirmed final security level"
                )
            if (
                SECURITY_LEVEL_RANK[user_selected_level]
                < SECURITY_LEVEL_RANK[recommendation.minimum_required_level]
            ):
                raise PolicyValidationError(
                    f"Selected level cannot be below the policy-required "
                    f"{recommendation.minimum_required_level.value}"
                )
            overridden = user_selected_level != recommendation.recommended_level
            reasons = recommendation.reasons
            if overridden:
                reasons += (
                    f"User increased the final level to {user_selected_level.value}.",
                )
            return SecurityDecision(
                selected_level=user_selected_level,
                minimum_required_level=recommendation.minimum_required_level,
                recommended_level=recommendation.recommended_level,
                kem_algorithm=self.level_policy.get_algorithm(user_selected_level),
                crypto_suite_id=self.level_policy.get_suite_id_for_architecture(user_selected_level, architecture),
                selection_mode=selection_mode,
                reasons=reasons,
                rules_triggered=recommendation.rules_triggered,
                policy_version=POLICY_VERSION,
                user_override=overridden,
                security_architecture=architecture,
            )

        raise PolicyValidationError(f"Unsupported selection mode: {selection_mode}")
