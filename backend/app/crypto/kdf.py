"""HKDF-SHA256 derivation with explicit salt and domain-separated info."""

from typing import Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.crypto.identifiers import HKDF_SHA256


class KDFProvider(Protocol):
    algorithm_id: str
    salt_size: int

    def derive(
        self,
        shared_secret: bytes,
        *,
        salt: bytes,
        info: bytes,
        length: int = 32,
    ) -> bytes: ...

    def self_test(self) -> None: ...


class HKDFSHA256Provider:
    algorithm_id = HKDF_SHA256
    salt_size = 32

    def derive(
        self,
        shared_secret: bytes,
        *,
        salt: bytes,
        info: bytes,
        length: int = 32,
    ) -> bytes:
        if not shared_secret:
            raise ValueError("Shared secret must not be empty")
        if len(salt) != self.salt_size:
            raise ValueError("HKDF-SHA256 requires a 32-byte salt")
        if not info:
            raise ValueError("HKDF-SHA256 info must not be empty")
        if length != 32:
            raise ValueError("QuantumShield file-key KEKs must be 32 bytes")
        return HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info,
        ).derive(shared_secret)

    def self_test(self) -> None:
        first = self.derive(b"S" * 32, salt=b"A" * 32, info=b"self-test")
        second = self.derive(b"S" * 32, salt=b"A" * 32, info=b"self-test")
        if first != second or len(first) != 32:
            raise RuntimeError("HKDF-SHA256 provider self-test failed")


# Backward-compatible name for existing callers.
HKDFService = HKDFSHA256Provider
