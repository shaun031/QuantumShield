"""Allow-listed KEM provider registry with no implicit fallback."""

from app.crypto.kem.base import KEMProvider
from app.crypto.identifiers import ML_KEM_1024, ML_KEM_512, ML_KEM_768


SUPPORTED_KEM_ALGORITHMS = (
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
)


class UnsupportedKEMAlgorithmError(ValueError):
    """Raised when stored/configured KEM metadata is not enabled."""


class KEMRegistry:
    def __init__(self, providers: tuple[KEMProvider, ...]) -> None:
        self._providers = {provider.algorithm_id: provider for provider in providers}
        if len(self._providers) != len(providers):
            raise ValueError("Duplicate KEM provider identifier")

    @property
    def enabled_algorithms(self) -> tuple[str, ...]:
        return tuple(self._providers)

    def get(self, algorithm: str) -> KEMProvider:
        try:
            return self._providers[algorithm]
        except KeyError as exc:
            raise UnsupportedKEMAlgorithmError(
                f"Unsupported KEM algorithm: {algorithm}"
            ) from exc

    def assert_available(self, algorithm: str) -> None:
        self.get(algorithm).self_test()

    def assert_all_available(self) -> None:
        for algorithm in SUPPORTED_KEM_ALGORITHMS:
            self.assert_available(algorithm)
