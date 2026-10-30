"""Safe Phase 9 provider and crypto-suite diagnostic (prints no key material)."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.crypto.aes import AESService
from app.crypto.kdf import HKDFService
from app.crypto.kem.factory import build_kem_registry
from app.crypto.key_wrap import AESGCMKeyWrapProvider
from app.crypto.provider_registry import ProviderRegistry
from app.crypto.suite_factory import build_crypto_suite_registry
from app.crypto.key_agreement import X25519Provider
from app.crypto.signature_profiles import build_signature_profile_registry
from scripts.check_hybrid import main as check_hybrid


def main() -> None:
    aead = AESService()
    kdf = HKDFService()
    key_wrap = AESGCMKeyWrapProvider(aead)
    kem_registry = build_kem_registry()
    suites = build_crypto_suite_registry(
        ProviderRegistry("AEAD", (aead,)),
        kem_registry,
        ProviderRegistry("KDF", (kdf,)),
        ProviderRegistry("key-wrap", (key_wrap,)),
    )
    suites.assert_all_available()
    X25519Provider().self_test()
    signing = build_signature_profile_registry().for_algorithm("ML-DSA-65").provider
    pair = signing.generate_keypair()
    signed = signing.sign(pair.private_key, b"QuantumShield diagnostic")
    if (not signing.verify(pair.public_key, b"QuantumShield diagnostic", signed)
        or signing.verify(pair.public_key, b"tampered diagnostic", signed)):
        raise RuntimeError("ML-DSA signature diagnostic failed")

    print("Provider self-tests: success")
    for suite in suites.get_supported_suites():
        print(
            f"{suite.suite_id} v{suite.version}: {suite.status.value}; "
            f"level={suite.security_level.value}; AEAD={suite.content_algorithm}; "
            f"KEM={suite.kem_algorithm}; KDF={suite.kdf_algorithm}; "
            f"key-wrap={suite.key_wrap_algorithm}"
            f"; architecture={suite.architecture.value}"
            f"; classical={suite.classical_algorithm or 'none'}"
        )
    print("Approved crypto suites available: yes")
    print("ML-DSA-65: available")
    print("Signature round trip: success")
    check_hybrid()


if __name__ == "__main__":
    main()
