"""Strict allow-listed registries for non-KEM provider roles."""

from typing import Generic, Protocol, TypeVar


class IdentifiedProvider(Protocol):
    algorithm_id: str

    def self_test(self) -> None: ...


ProviderT = TypeVar("ProviderT", bound=IdentifiedProvider)


class UnsupportedProviderError(ValueError):
    pass


class ProviderRegistry(Generic[ProviderT]):
    def __init__(self, role: str, providers: tuple[ProviderT, ...]) -> None:
        self.role = role
        self._providers = {provider.algorithm_id: provider for provider in providers}
        if len(self._providers) != len(providers):
            raise ValueError(f"Duplicate {role} provider identifier")

    @property
    def enabled_algorithms(self) -> tuple[str, ...]:
        return tuple(self._providers)

    def get(self, algorithm_id: str) -> ProviderT:
        try:
            return self._providers[algorithm_id]
        except KeyError as exc:
            raise UnsupportedProviderError(
                f"Unsupported {self.role} algorithm: {algorithm_id}"
            ) from exc

    def assert_all_available(self) -> None:
        for provider in self._providers.values():
            provider.self_test()
