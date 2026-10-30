"""Trusted crypto-suite model and strict lifecycle-aware registry."""

from dataclasses import dataclass
from enum import StrEnum

from app.crypto.aead import AEADProvider
from app.crypto.kdf import KDFProvider
from app.crypto.kem.base import KEMProvider
from app.crypto.key_wrap import KeyWrapProvider
from app.crypto.security_levels import SecurityLevel


class SecurityArchitecture(StrEnum):
    PQ_ONLY = "PQ_ONLY"
    HYBRID = "HYBRID"


class CryptoSuiteStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


class UnsupportedCryptoSuiteError(ValueError):
    pass


class CryptoSuiteNotActiveError(ValueError):
    pass


class CryptoSuiteMismatchError(ValueError):
    pass


@dataclass(frozen=True)
class CryptoSuite:
    suite_id: str
    version: int
    security_level: SecurityLevel
    content_aead: AEADProvider
    kem: KEMProvider
    kdf: KDFProvider
    key_wrap: KeyWrapProvider
    description: str
    status: CryptoSuiteStatus = CryptoSuiteStatus.ACTIVE
    architecture: SecurityArchitecture = SecurityArchitecture.PQ_ONLY
    classical_algorithm: str | None = None

    @property
    def content_algorithm(self) -> str:
        return self.content_aead.algorithm_id

    @property
    def kem_algorithm(self) -> str:
        return self.kem.algorithm_id

    @property
    def kdf_algorithm(self) -> str:
        return self.kdf.algorithm_id

    @property
    def key_wrap_algorithm(self) -> str:
        return self.key_wrap.algorithm_id


class CryptoSuiteRegistry:
    def __init__(self, suites: tuple[CryptoSuite, ...]) -> None:
        self._suites = {suite.suite_id: suite for suite in suites}
        if len(self._suites) != len(suites):
            raise ValueError("Duplicate crypto suite identifier")
        levels = [(suite.architecture, suite.security_level) for suite in suites if suite.status is CryptoSuiteStatus.ACTIVE]
        if len(levels) != len(set(levels)):
            raise ValueError("More than one active suite is mapped to a security level")

    def get_suite(self, suite_id: str, *, for_encryption: bool = False) -> CryptoSuite:
        try:
            suite = self._suites[suite_id]
        except KeyError as exc:
            raise UnsupportedCryptoSuiteError(
                f"Unsupported crypto suite: {suite_id}"
            ) from exc
        if suite.status is CryptoSuiteStatus.DISABLED:
            raise UnsupportedCryptoSuiteError(f"Disabled crypto suite: {suite_id}")
        if for_encryption and suite.status is not CryptoSuiteStatus.ACTIVE:
            raise CryptoSuiteNotActiveError(
                f"Crypto suite is not active for new encryption: {suite_id}"
            )
        return suite

    def get_suite_for_security_level(
        self, level: SecurityLevel | str, architecture: SecurityArchitecture | str = SecurityArchitecture.PQ_ONLY
    ) -> CryptoSuite:
        normalized = level if isinstance(level, SecurityLevel) else SecurityLevel(level)
        selected_architecture = SecurityArchitecture(architecture)
        for suite in self._suites.values():
            if (
                suite.security_level is normalized
                and suite.architecture is selected_architecture
                and suite.status is CryptoSuiteStatus.ACTIVE
            ):
                return suite
        raise UnsupportedCryptoSuiteError(
            f"No active crypto suite for security level: {normalized.value}"
        )

    def get_supported_suites(self) -> tuple[CryptoSuite, ...]:
        return tuple(self._suites.values())

    def validate_metadata(
        self,
        *,
        suite_id: str,
        suite_version: int,
        security_level: SecurityLevel | str,
        content_algorithm: str,
        kem_algorithm: str,
        kdf_algorithm: str,
        key_wrap_algorithm: str,
        architecture: SecurityArchitecture | str = SecurityArchitecture.PQ_ONLY,
        classical_algorithm: str | None = None,
    ) -> CryptoSuite:
        suite = self.get_suite(suite_id)
        normalized = (
            security_level
            if isinstance(security_level, SecurityLevel)
            else SecurityLevel(security_level)
        )
        actual = (
            suite.version,
            suite.security_level,
            suite.content_algorithm,
            suite.kem_algorithm,
            suite.kdf_algorithm,
            suite.key_wrap_algorithm,
            suite.architecture,
            suite.classical_algorithm,
        )
        expected = (
            suite_version,
            normalized,
            content_algorithm,
            kem_algorithm,
            kdf_algorithm,
            key_wrap_algorithm,
            SecurityArchitecture(architecture),
            classical_algorithm,
        )
        if actual != expected:
            raise CryptoSuiteMismatchError(
                "Stored crypto metadata does not match its registered suite"
            )
        return suite

    def assert_all_available(self) -> None:
        tested: set[tuple[str, str]] = set()
        for suite in self._suites.values():
            for role, provider in (
                ("AEAD", suite.content_aead),
                ("KEM", suite.kem),
                ("KDF", suite.kdf),
                ("KeyWrap", suite.key_wrap),
            ):
                identity = (role, provider.algorithm_id)
                if identity not in tested:
                    provider.self_test()
                    tested.add(identity)
