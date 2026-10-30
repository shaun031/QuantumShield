"""Deterministic Phase 8 policy-engine unit tests."""

import pytest

from app.crypto.security_levels import SECURITY_LEVEL_RANK, SecurityLevel
from app.services.security_policy import (
    POLICY_VERSION,
    DocumentCategory,
    PolicyValidationError,
    SecurityAssessmentInput,
    SecurityPolicyEngine,
    SelectionMode,
    Sensitivity,
)


def assessment(
    *,
    file_name: str = "document.txt",
    sensitivity: Sensitivity | None = None,
    category: DocumentCategory | None = None,
) -> SecurityAssessmentInput:
    return SecurityAssessmentInput(
        file_name=file_name,
        file_size=1234,
        mime_type="application/octet-stream",
        sensitivity=sensitivity,
        document_category=category,
    )


@pytest.mark.parametrize(
    ("sensitivity", "category", "expected"),
    [
        (Sensitivity.PUBLIC, DocumentCategory.GENERAL, SecurityLevel.LOW),
        (Sensitivity.INTERNAL, DocumentCategory.GENERAL, SecurityLevel.STANDARD),
        (Sensitivity.CONFIDENTIAL, DocumentCategory.GENERAL, SecurityLevel.HIGH),
        (Sensitivity.HIGHLY_CONFIDENTIAL, None, SecurityLevel.HIGH),
        (Sensitivity.PUBLIC, DocumentCategory.MEDICAL, SecurityLevel.HIGH),
        (Sensitivity.PUBLIC, DocumentCategory.FINANCIAL, SecurityLevel.STANDARD),
        (None, DocumentCategory.CREDENTIALS, SecurityLevel.HIGH),
    ],
)
def test_policy_matrix_uses_strongest_rule(
    sensitivity: Sensitivity | None,
    category: DocumentCategory | None,
    expected: SecurityLevel,
) -> None:
    decision = SecurityPolicyEngine().recommend_level(
        assessment(sensitivity=sensitivity, category=category)
    )

    assert decision.recommended_level is expected
    assert decision.minimum_required_level is expected
    assert decision.policy_version == POLICY_VERSION
    assert decision.kem_algorithm == {
        SecurityLevel.LOW: "ML-KEM-512",
        SecurityLevel.STANDARD: "ML-KEM-768",
        SecurityLevel.HIGH: "ML-KEM-1024",
    }[expected]


def test_no_signals_defaults_to_standard_and_secret_extension_requires_high() -> None:
    engine = SecurityPolicyEngine()
    default = engine.recommend_level(assessment())
    secret = engine.recommend_level(assessment(file_name="service.env"))

    assert default.recommended_level is SecurityLevel.STANDARD
    assert default.rules_triggered[0].rule == "default"
    assert secret.recommended_level is SecurityLevel.HIGH
    assert secret.rules_triggered[0].rule == "file_extension"


def test_strongest_rule_collects_all_explanations() -> None:
    decision = SecurityPolicyEngine().recommend_level(
        assessment(
            sensitivity=Sensitivity.INTERNAL,
            category=DocumentCategory.MEDICAL,
        )
    )

    assert decision.recommended_level is SecurityLevel.HIGH
    assert [result.rule for result in decision.rules_triggered] == [
        "sensitivity",
        "document_category",
    ]
    assert any("INTERNAL" in reason for reason in decision.reasons)
    assert any("MEDICAL" in reason for reason in decision.reasons)


@pytest.mark.parametrize(
    ("level", "algorithm"),
    [
        (SecurityLevel.LOW, "ML-KEM-512"),
        (SecurityLevel.STANDARD, "ML-KEM-768"),
        (SecurityLevel.HIGH, "ML-KEM-1024"),
    ],
)
def test_manual_mode_preserves_phase7_selection(
    level: SecurityLevel, algorithm: str
) -> None:
    decision = SecurityPolicyEngine().evaluate(
        assessment(), SelectionMode.MANUAL, level
    )

    assert decision.selected_level is level
    assert decision.kem_algorithm == algorithm
    assert decision.reasons == (f"User manually selected {level.value}.",)


def test_recommend_allows_increase_but_rejects_downgrade() -> None:
    engine = SecurityPolicyEngine()
    public = assessment(
        sensitivity=Sensitivity.PUBLIC,
        category=DocumentCategory.GENERAL,
    )
    increased = engine.evaluate(public, SelectionMode.RECOMMEND, SecurityLevel.HIGH)

    assert increased.recommended_level is SecurityLevel.LOW
    assert increased.selected_level is SecurityLevel.HIGH
    assert increased.user_override is True

    confidential = assessment(sensitivity=Sensitivity.CONFIDENTIAL)
    with pytest.raises(PolicyValidationError, match="below the policy-required HIGH"):
        engine.evaluate(
            confidential,
            SelectionMode.RECOMMEND,
            SecurityLevel.STANDARD,
        )


def test_auto_rejects_explicit_level_and_is_deterministic() -> None:
    engine = SecurityPolicyEngine()
    value = assessment(
        sensitivity=Sensitivity.PUBLIC,
        category=DocumentCategory.FINANCIAL,
    )
    first = engine.evaluate(value, SelectionMode.AUTO)
    second = engine.evaluate(value, SelectionMode.AUTO)

    assert first == second
    assert first.selected_level is SecurityLevel.STANDARD
    with pytest.raises(PolicyValidationError, match="does not accept"):
        engine.evaluate(value, SelectionMode.AUTO, SecurityLevel.LOW)


def test_security_rank_is_explicit() -> None:
    assert SECURITY_LEVEL_RANK[SecurityLevel.LOW] < SECURITY_LEVEL_RANK[SecurityLevel.STANDARD]
    assert SECURITY_LEVEL_RANK[SecurityLevel.STANDARD] < SECURITY_LEVEL_RANK[SecurityLevel.HIGH]
