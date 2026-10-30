"""Typed KEM interfaces kept independent from any concrete library API."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class KEMKeyPair:
    public_key: bytes
    private_key: bytes


@dataclass(frozen=True)
class KEMEncapsulation:
    ciphertext: bytes
    shared_secret: bytes


class KEMProvider(Protocol):
    algorithm_id: str
    public_key_size: int
    private_key_size: int
    ciphertext_size: int
    shared_secret_size: int

    def generate_keypair(self) -> KEMKeyPair: ...

    def encapsulate(self, public_key: bytes) -> KEMEncapsulation: ...

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes: ...

    def self_test(self) -> None: ...
