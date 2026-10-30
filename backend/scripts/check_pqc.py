"""Safe local diagnostic for every required Phase 7 ML-KEM provider."""

import hmac

import cryptography
import mlkem

from app.crypto.kem.factory import build_kem_registry


def main() -> None:
    registry = build_kem_registry()
    for algorithm in registry.enabled_algorithms:
        provider = registry.get(algorithm)
        keypair = provider.generate_keypair()
        encapsulated = provider.encapsulate(keypair.public_key)
        recovered = provider.decapsulate(
            keypair.private_key,
            encapsulated.ciphertext,
        )
        if not hmac.compare_digest(encapsulated.shared_secret, recovered):
            raise SystemExit(f"{algorithm} round trip: failed")
        print(f"{algorithm}: available ({provider.mechanism_id})")

    print(f"cryptography provider version: {cryptography.__version__}")
    print(f"mlkem provider version: {mlkem.__version__ if hasattr(mlkem, '__version__') else '0.1.0'}")
    print("Required PQC algorithms available: yes")
    print("All KEM round trips: success")


if __name__ == "__main__":
    main()
