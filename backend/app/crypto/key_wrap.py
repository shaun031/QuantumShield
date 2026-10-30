"""File-key wrapping provider contract and AES-GCM implementation."""

from typing import Protocol

from app.crypto.aead import AEADProvider
from app.crypto.aes import AeadCiphertext
from app.crypto.identifiers import KEK_AES_256_GCM


class KeyWrapProvider(Protocol):
    algorithm_id: str
    wrapping_key_size: int
    nonce_size: int

    def wrap_key(
        self,
        key_to_wrap: bytes,
        wrapping_key: bytes,
        context: bytes,
    ) -> AeadCiphertext: ...

    def unwrap_key(
        self,
        wrapped_key: bytes,
        wrapping_key: bytes,
        nonce: bytes,
        context: bytes,
    ) -> bytes: ...

    def self_test(self) -> None: ...


class AESGCMKeyWrapProvider:
    algorithm_id = KEK_AES_256_GCM
    wrapping_key_size = 32
    nonce_size = 12

    def __init__(self, aead: AEADProvider) -> None:
        self.aead = aead

    def wrap_key(
        self,
        key_to_wrap: bytes,
        wrapping_key: bytes,
        context: bytes,
    ) -> AeadCiphertext:
        if len(key_to_wrap) != 32:
            raise ValueError("QuantumShield file keys must be 32 bytes")
        return self.aead.encrypt(key_to_wrap, wrapping_key, context)

    def unwrap_key(
        self,
        wrapped_key: bytes,
        wrapping_key: bytes,
        nonce: bytes,
        context: bytes,
    ) -> bytes:
        recovered = self.aead.decrypt(wrapped_key, wrapping_key, nonce, context)
        if len(recovered) != 32:
            raise ValueError("Recovered file key has an invalid length")
        return recovered

    def self_test(self) -> None:
        wrapping_key = b"W" * 32
        file_key = b"F" * 32
        context = b"QuantumShield/KeyWrapSelfTest/v1"
        wrapped = self.wrap_key(file_key, wrapping_key, context)
        if self.unwrap_key(
            wrapped.ciphertext,
            wrapping_key,
            wrapped.nonce,
            context,
        ) != file_key:
            raise RuntimeError("AES-GCM key-wrap provider self-test failed")
