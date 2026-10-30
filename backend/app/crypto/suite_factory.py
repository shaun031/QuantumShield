"""Compose approved suites from injected provider registries."""

from app.crypto.aead import AEADProvider
from app.crypto.kdf import KDFProvider
from app.crypto.kem.registry import KEMRegistry
from app.crypto.key_wrap import KeyWrapProvider
from app.crypto.provider_registry import ProviderRegistry
from app.crypto.security_levels import SecurityLevel
from app.crypto.suite_specs import APPROVED_SUITE_SPECS
from app.crypto.suites import CryptoSuite, CryptoSuiteRegistry, SecurityArchitecture


def build_crypto_suite_registry(
    aead_registry: ProviderRegistry[AEADProvider],
    kem_registry: KEMRegistry,
    kdf_registry: ProviderRegistry[KDFProvider],
    key_wrap_registry: ProviderRegistry[KeyWrapProvider],
) -> CryptoSuiteRegistry:
    return CryptoSuiteRegistry(
        tuple(
            CryptoSuite(
                suite_id=spec.suite_id,
                version=spec.version,
                security_level=SecurityLevel(spec.security_level),
                content_aead=aead_registry.get(spec.content_aead),
                kem=kem_registry.get(spec.kem),
                kdf=kdf_registry.get(spec.kdf),
                key_wrap=key_wrap_registry.get(spec.key_wrap),
                description=spec.description,
                architecture=SecurityArchitecture(spec.architecture),
                classical_algorithm=spec.classical_algorithm,
            )
            for spec in APPROVED_SUITE_SPECS
        )
    )
