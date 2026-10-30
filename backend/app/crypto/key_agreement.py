"""Raw X25519 key agreement with mandatory low-order-point rejection."""

from dataclasses import dataclass
from typing import Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from app.crypto.identifiers import X25519


@dataclass(frozen=True)
class AgreementKeyPair:
    public_key: bytes
    private_key: bytes


class KeyAgreementProvider(Protocol):
    algorithm_id: str
    public_key_size: int
    private_key_size: int
    shared_secret_size: int

    def generate_keypair(self) -> AgreementKeyPair: ...
    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes: ...
    def self_test(self) -> None: ...


class X25519Provider:
    algorithm_id = X25519
    public_key_size = 32
    private_key_size = 32
    shared_secret_size = 32

    def generate_keypair(self) -> AgreementKeyPair:
        private = x25519.X25519PrivateKey.generate()
        return AgreementKeyPair(
            private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
        )

    def derive_shared_secret(self, private_key: bytes, peer_public_key: bytes) -> bytes:
        if len(private_key) != 32 or len(peer_public_key) != 32:
            raise ValueError("Invalid X25519 key length")
        secret = x25519.X25519PrivateKey.from_private_bytes(private_key).exchange(
            x25519.X25519PublicKey.from_public_bytes(peer_public_key)
        )
        if secret == bytes(32):
            raise ValueError("Invalid X25519 shared secret")
        return secret

    def self_test(self) -> None:
        left = self.generate_keypair()
        right = self.generate_keypair()
        if self.derive_shared_secret(left.private_key, right.public_key) != self.derive_shared_secret(
            right.private_key, left.public_key
        ):
            raise RuntimeError("X25519 self-test failed")
