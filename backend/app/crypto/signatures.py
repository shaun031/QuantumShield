"""Maintained ML-DSA signing adapters; native objects never leave this boundary."""

from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa

from app.crypto.identifiers import ML_DSA_44, ML_DSA_65, ML_DSA_87


@dataclass(frozen=True)
class SigningKeyPair:
    public_key: bytes
    private_key: bytes


class SignatureProvider(Protocol):
    algorithm_id: str
    public_key_size: int
    private_key_size: int
    signature_size: int

    def generate_keypair(self) -> SigningKeyPair: ...
    def sign(self, private_key: bytes, message: bytes) -> bytes: ...
    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...
    def self_test(self) -> None: ...


_TYPES = {
    ML_DSA_44: (mldsa.MLDSA44PrivateKey, mldsa.MLDSA44PublicKey, 1312, 2420),
    ML_DSA_65: (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey, 1952, 3309),
    ML_DSA_87: (mldsa.MLDSA87PrivateKey, mldsa.MLDSA87PublicKey, 2592, 4627),
}


class MLDSAProvider:
    private_key_size = 32  # raw FIPS 204 seed, not an expanded secret key

    def __init__(self, algorithm_id: str) -> None:
        try:
            self._private_type, self._public_type, self.public_key_size, self.signature_size = _TYPES[algorithm_id]
        except KeyError as exc:
            raise ValueError("Unsupported ML-DSA algorithm") from exc
        self.algorithm_id = algorithm_id

    def generate_keypair(self) -> SigningKeyPair:
        private = self._private_type.generate()
        return SigningKeyPair(private.public_key().public_bytes_raw(), private.private_bytes_raw())

    def sign(self, private_key: bytes, message: bytes) -> bytes:
        if len(private_key) != self.private_key_size:
            raise ValueError("Invalid ML-DSA private seed length")
        signature = self._private_type.from_seed_bytes(private_key).sign(message)
        if len(signature) != self.signature_size:
            raise ValueError("Invalid ML-DSA signature length")
        return signature

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if len(public_key) != self.public_key_size or len(signature) != self.signature_size:
            return False
        try:
            self._public_type.from_public_bytes(public_key).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

    def self_test(self) -> None:
        pair = self.generate_keypair()
        signature = self.sign(pair.private_key, b"QuantumShield/SignatureSelfTest/v1")
        if (not self.verify(pair.public_key, b"QuantumShield/SignatureSelfTest/v1", signature)
            or self.verify(pair.public_key, b"tampered", signature)):
            raise RuntimeError("ML-DSA provider self-test failed")
