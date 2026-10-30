"""Authenticated-encryption provider contract."""

from typing import Protocol

from app.crypto.aes import AeadCiphertext


class AEADProvider(Protocol):
    algorithm_id: str
    key_size: int
    nonce_size: int

    def generate_key(self) -> bytes: ...

    def generate_nonce(self) -> bytes: ...

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        aad: bytes,
        nonce: bytes | None = None,
    ) -> AeadCiphertext: ...

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        aad: bytes,
    ) -> bytes: ...

    def self_test(self) -> None: ...
