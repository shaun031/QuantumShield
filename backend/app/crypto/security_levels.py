"""Explicit Phase 7 security levels and canonical ML-KEM mapping."""

from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.crypto.suites import CryptoSuiteRegistry


class SecurityLevel(StrEnum):
    LOW = "LOW"
    STANDARD = "STANDARD"
    HIGH = "HIGH"


class SecurityLevelRank(IntEnum):
    """Policy ordering; security levels are never compared alphabetically."""

    LOW = 1
    STANDARD = 2
    HIGH = 3


SECURITY_LEVEL_RANK = {
    SecurityLevel.LOW: SecurityLevelRank.LOW,
    SecurityLevel.STANDARD: SecurityLevelRank.STANDARD,
    SecurityLevel.HIGH: SecurityLevelRank.HIGH,
}


@dataclass(frozen=True)
class SecurityLevelChoice:
    security_level: SecurityLevel
    suite_id: str
    algorithm: str
    description: str
    is_default: bool


class SecurityLevelPolicy:
    """Validate explicit selections; never classify or recommend a file."""

    descriptions = {
        SecurityLevel.LOW: "Lower key and ciphertext overhead",
        SecurityLevel.STANDARD: "Recommended default for this project",
        SecurityLevel.HIGH: "Largest supported ML-KEM parameter set",
    }

    def __init__(
        self,
        default_level: SecurityLevel = SecurityLevel.STANDARD,
        suite_registry: "CryptoSuiteRegistry | None" = None,
    ) -> None:
        self.default_level = default_level
        self.suite_registry = suite_registry

    def get_algorithm(self, level: SecurityLevel | str) -> str:
        """Compatibility accessor backed by the approved suite specification."""
        if self.suite_registry is not None:
            return self.suite_registry.get_suite_for_security_level(level).kem_algorithm
        from app.crypto.suite_specs import SUITE_SPEC_BY_LEVEL

        try:
            normalized = level if isinstance(level, SecurityLevel) else SecurityLevel(level)
            return SUITE_SPEC_BY_LEVEL[normalized.value].kem
        except (ValueError, KeyError) as exc:
            raise ValueError(f"Unsupported security level: {level}") from exc

    def get_suite_id(self, level: SecurityLevel | str) -> str:
        if self.suite_registry is not None:
            return self.suite_registry.get_suite_for_security_level(level).suite_id
        from app.crypto.suite_specs import SUITE_SPEC_BY_LEVEL

        try:
            normalized = level if isinstance(level, SecurityLevel) else SecurityLevel(level)
            return SUITE_SPEC_BY_LEVEL[normalized.value].suite_id
        except (ValueError, KeyError) as exc:
            raise ValueError(f"Unsupported security level: {level}") from exc

    def get_suite_id_for_architecture(self, level: SecurityLevel | str, architecture: "SecurityArchitecture") -> str:
        from app.crypto.suites import SecurityArchitecture
        from app.crypto.suite_specs import APPROVED_SUITE_SPECS
        selected = SecurityArchitecture(architecture)
        if self.suite_registry is not None:
            return self.suite_registry.get_suite_for_security_level(level, selected).suite_id
        normalized = SecurityLevel(level)
        return next(spec.suite_id for spec in APPROVED_SUITE_SPECS
                    if spec.security_level == normalized.value and spec.architecture == selected.value)

    def get_level(self, algorithm: str) -> SecurityLevel:
        from app.crypto.suite_specs import APPROVED_SUITE_SPECS

        for spec in APPROVED_SUITE_SPECS:
            if spec.kem == algorithm and spec.architecture == "PQ_ONLY":
                return SecurityLevel(spec.security_level)
        raise ValueError(f"Unsupported KEM algorithm: {algorithm}")

    def validate_pair(self, level: SecurityLevel | str, algorithm: str) -> None:
        if self.get_algorithm(level) != algorithm:
            raise ValueError("Security level and KEM algorithm do not match")

    def get_supported_levels(self) -> tuple[SecurityLevelChoice, ...]:
        if self.suite_registry is not None:
            from app.crypto.suites import CryptoSuiteStatus

            active = {
                suite.security_level: suite
                for suite in self.suite_registry.get_supported_suites()
                if suite.status is CryptoSuiteStatus.ACTIVE and suite.architecture.value == "PQ_ONLY"
            }
            return tuple(
                SecurityLevelChoice(
                    security_level=level,
                    suite_id=active[level].suite_id,
                    algorithm=active[level].kem_algorithm,
                    description=self.descriptions[level],
                    is_default=level == self.default_level,
                )
                for level in SecurityLevel
                if level in active
            )
        return tuple(
            SecurityLevelChoice(
                security_level=level,
                suite_id=suite_id,
                algorithm=algorithm,
                description=self.descriptions[level],
                is_default=level == self.default_level,
            )
            for level in SecurityLevel
            for suite_id, algorithm in ((self.get_suite_id(level), self.get_algorithm(level)),)
        )
