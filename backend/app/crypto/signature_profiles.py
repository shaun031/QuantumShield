"""Closed signing-profile registry independent of confidentiality suites."""

from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache

from app.crypto.identifiers import ML_DSA_44, ML_DSA_65, ML_DSA_87
from app.crypto.provider_registry import ProviderRegistry
from app.crypto.signatures import MLDSAProvider, SignatureProvider


class SignatureProfileStatus(StrEnum):
    ACTIVE = "ACTIVE"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"


@dataclass(frozen=True)
class SignatureProfile:
    profile_id: str
    algorithm: str
    payload_version: int
    provider: SignatureProvider
    status: SignatureProfileStatus = SignatureProfileStatus.ACTIVE


class SignatureProfileRegistry:
    def __init__(self, profiles: tuple[SignatureProfile, ...]) -> None:
        self._profiles = {profile.profile_id: profile for profile in profiles}
        if len(self._profiles) != len(profiles):
            raise ValueError("Duplicate signature profile")

    def get(self, profile_id: str, *, for_signing: bool = False) -> SignatureProfile:
        try:
            profile = self._profiles[profile_id]
        except KeyError as exc:
            raise ValueError("Unknown signature profile") from exc
        if (profile.status is SignatureProfileStatus.DISABLED
            or (for_signing and profile.status is not SignatureProfileStatus.ACTIVE)):
            raise ValueError("Signature profile is unavailable")
        return profile

    def for_algorithm(self, algorithm: str, *, for_signing: bool = False) -> SignatureProfile:
        return self.get(f"QS-SIG-{algorithm.replace('-', '')}-V1", for_signing=for_signing)

    def all(self) -> tuple[SignatureProfile, ...]:
        return tuple(self._profiles.values())

    def assert_all_available(self) -> None:
        for profile in self._profiles.values():
            profile.provider.self_test()


@lru_cache(maxsize=1)
def build_signature_profile_registry() -> SignatureProfileRegistry:
    providers = ProviderRegistry("signature", tuple(MLDSAProvider(name) for name in (ML_DSA_44, ML_DSA_65, ML_DSA_87)))
    registry = SignatureProfileRegistry(tuple(
        SignatureProfile(f"QS-SIG-{name.replace('-', '')}-V1", name, 1, providers.get(name))
        for name in (ML_DSA_44, ML_DSA_65, ML_DSA_87)
    ))
    registry.assert_all_available()
    return registry
