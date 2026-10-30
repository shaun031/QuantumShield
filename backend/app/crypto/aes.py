"""Small AES-256-GCM provider built on the high-level cryptography API."""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.crypto.identifiers import AES_256_GCM


AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12


@dataclass(frozen=True)
class AeadCiphertext:
    nonce: bytes
    ciphertext: bytes


class AES256GCMProvider:
    """The only approved Phase 9 AEAD provider."""

    algorithm_id = AES_256_GCM
    key_size = AES_KEY_BYTES
    nonce_size = GCM_NONCE_BYTES

    def generate_key(self) -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def generate_nonce(self) -> bytes:
        return os.urandom(self.nonce_size)

    def encrypt(
        self,
        plaintext: bytes,
        key: bytes,
        aad: bytes,
        nonce: bytes | None = None,
    ) -> AeadCiphertext:
        if len(key) != AES_KEY_BYTES:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        nonce = nonce if nonce is not None else self.generate_nonce()
        if len(nonce) != self.nonce_size:
            raise ValueError("AES-256-GCM requires a 12-byte nonce")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
        return AeadCiphertext(nonce=nonce, ciphertext=ciphertext)

    def decrypt(
        self,
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        aad: bytes,
    ) -> bytes:
        if len(key) != AES_KEY_BYTES:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        if len(nonce) != GCM_NONCE_BYTES:
            raise ValueError("AES-256-GCM requires a 12-byte nonce")
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def self_test(self) -> None:
        key = self.generate_key()
        aad = b"QuantumShield/AEADSelfTest/v1"
        protected = self.encrypt(b"provider-self-test", key, aad)
        if self.decrypt(protected.ciphertext, key, protected.nonce, aad) != b"provider-self-test":
            raise RuntimeError("AES-256-GCM provider self-test failed")


# Backward-compatible name for Phase 4-8 imports and historical tests.
AESService = AES256GCMProvider
