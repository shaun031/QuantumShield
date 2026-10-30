"""Canonical FIPS 203 ML-KEM adapters behind the application KEM protocol."""

import hmac
from typing import Any

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM1024PrivateKey,
    MLKEM1024PublicKey,
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
)
from mlkem import ML_KEM, ParameterSet

from app.crypto.kem.base import KEMEncapsulation, KEMKeyPair
from app.crypto.identifiers import ML_KEM_1024, ML_KEM_512, ML_KEM_768


MLKEM_SIZES = {
    ML_KEM_512: (800, 1632, 768, 32),
    ML_KEM_768: (1184, 64, 1088, 32),
    ML_KEM_1024: (1568, 64, 1568, 32),
}


class MLKEMProvider:
    """Map canonical application names to maintained library mechanisms."""

    def __init__(self, algorithm_id: str) -> None:
        if algorithm_id not in MLKEM_SIZES:
            raise ValueError(f"Unsupported ML-KEM provider: {algorithm_id}")
        self.algorithm_id = algorithm_id
        (
            self.public_key_size,
            self.private_key_size,
            self.ciphertext_size,
            self.shared_secret_size,
        ) = MLKEM_SIZES[algorithm_id]

    @property
    def mechanism_id(self) -> str:
        if self.algorithm_id == ML_KEM_512:
            return "mlkem.ParameterSet.ML_KEM_512"
        return f"cryptography.{self.algorithm_id.replace('-', '')}PrivateKey"

    def _cryptography_types(self) -> tuple[type[Any], type[Any]]:
        if self.algorithm_id == ML_KEM_768:
            return MLKEM768PrivateKey, MLKEM768PublicKey
        if self.algorithm_id == ML_KEM_1024:
            return MLKEM1024PrivateKey, MLKEM1024PublicKey
        raise ValueError("ML-KEM-512 uses the mlkem provider")

    def generate_keypair(self) -> KEMKeyPair:
        if self.algorithm_id == ML_KEM_512:
            public_key, private_key = ML_KEM(ParameterSet.ML_KEM_512).key_gen()
            return KEMKeyPair(public_key=public_key, private_key=private_key)
        private_type, _ = self._cryptography_types()
        private_key = private_type.generate()
        return KEMKeyPair(
            public_key=private_key.public_key().public_bytes_raw(),
            private_key=private_key.private_bytes_raw(),
        )

    def encapsulate(self, public_key: bytes) -> KEMEncapsulation:
        if len(public_key) != self.public_key_size:
            raise ValueError(f"Invalid {self.algorithm_id} public key")
        if self.algorithm_id == ML_KEM_512:
            shared_secret, ciphertext = ML_KEM(ParameterSet.ML_KEM_512).encaps(
                public_key
            )
        else:
            _, public_type = self._cryptography_types()
            shared_secret, ciphertext = public_type.from_public_bytes(
                public_key
            ).encapsulate()
        return KEMEncapsulation(ciphertext=ciphertext, shared_secret=shared_secret)

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        if len(private_key) != self.private_key_size:
            raise ValueError(f"Invalid {self.algorithm_id} private key")
        if len(ciphertext) != self.ciphertext_size:
            raise ValueError(f"Invalid {self.algorithm_id} ciphertext")
        if self.algorithm_id == ML_KEM_512:
            return ML_KEM(ParameterSet.ML_KEM_512).decaps(private_key, ciphertext)
        private_type, _ = self._cryptography_types()
        return private_type.from_seed_bytes(private_key).decapsulate(ciphertext)

    def self_test(self) -> None:
        keypair = self.generate_keypair()
        encapsulated = self.encapsulate(keypair.public_key)
        recovered = self.decapsulate(keypair.private_key, encapsulated.ciphertext)
        if not hmac.compare_digest(encapsulated.shared_secret, recovered):
            raise RuntimeError(f"{self.algorithm_id} provider self-test failed")


class MLKEM512Provider(MLKEMProvider):
    def __init__(self) -> None:
        super().__init__(ML_KEM_512)


class MLKEM768Provider(MLKEMProvider):
    def __init__(self) -> None:
        super().__init__(ML_KEM_768)


class MLKEM1024Provider(MLKEMProvider):
    def __init__(self) -> None:
        super().__init__(ML_KEM_1024)
