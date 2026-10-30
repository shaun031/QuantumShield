"""Safe Phase 10 round-trip diagnostic; never prints keys or secrets."""

from uuid import uuid4

from app.crypto.aes import AESService
from app.crypto.kdf import HKDFService
from app.crypto.kem.factory import build_kem_registry
from app.crypto.key_agreement import X25519Provider
from app.crypto.key_wrap import AESGCMKeyWrapProvider
from app.crypto.provider_registry import ProviderRegistry
from app.crypto.suite_factory import build_crypto_suite_registry
from app.crypto.hybrid_key_protection import HybridContext, HybridKeyProtector


def main() -> None:
    aes = AESService()
    kdf = HKDFService()
    kem = build_kem_registry()
    agreement = X25519Provider()
    agreement.self_test()
    suites = build_crypto_suite_registry(
        ProviderRegistry("AEAD", (aes,)), kem,
        ProviderRegistry("KDF", (kdf,)),
        ProviderRegistry("key-wrap", (AESGCMKeyWrapProvider(aes),)),
    )
    suites.assert_all_available()
    protector = HybridKeyProtector(suites, agreement)
    for level, size in (("LOW",512),("STANDARD",768),("HIGH",1024)):
        suite = suites.get_suite(f"QS-HYBRID-{size}-V1", for_encryption=True)
        pq = suite.kem.generate_keypair()
        classical = agreement.generate_keypair()
        owner = uuid4()
        context = HybridContext(
            purpose="OWNER", file_id=uuid4(), owner_id=owner, recipient_id=owner,
            recipient_kem_key_id=uuid4(), recipient_kem_key_version=1,
            recipient_classical_key_id=uuid4(), recipient_classical_key_version=1,
            suite_id=suite.suite_id, suite_version=suite.version,
            security_level=level, plaintext_size=7, crypto_version=4, aad_version=4,
        )
        protected = protector.protect(b"F" * 32, pq.public_key, classical.public_key, context)
        recovered = protector.recover(
            kem_private_key=pq.private_key, classical_private_key=classical.private_key,
            classical_public_key=classical.public_key,
            ephemeral_public_key=protected.ephemeral_public_key,
            kem_ciphertext=protected.kem_ciphertext, kdf_salt=protected.kdf_salt,
            wrapped_file_key=protected.wrapped_file_key,
            key_wrap_nonce=protected.key_wrap_nonce, context=context)
        if recovered != b"F" * 32:
            raise SystemExit(f"{suite.suite_id}: failed")
        print(f"{suite.suite_id}: hybrid round trip passed")
    print("Hybrid provider diagnostics: success")


if __name__ == "__main__":
    main()
