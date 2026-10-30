"""Master-key authenticated protection for server-managed private keys."""

from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag

from app.crypto.aes import AESService, AeadCiphertext


PRIVATE_KEY_PROTECTION_ALGORITHM = "MASTER-AES-256-GCM"
PRIVATE_KEY_PROTECTION_VERSION = 1
_PRIVATE_KEY_DOMAIN = b"QuantumShield/UserPrivateKey/v1"


class SecretProtectionError(ValueError):
    """Raised when an encrypted private key cannot be authenticated."""


@dataclass(frozen=True)
class SecretContext:
    user_id: UUID
    key_id: UUID
    algorithm: str
    key_version: int


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def encode_private_key_aad(context: SecretContext) -> bytes:
    if context.key_version < 1:
        raise ValueError("Key version must be positive")
    return b"".join(
        (
            _length_prefix(_PRIVATE_KEY_DOMAIN),
            PRIVATE_KEY_PROTECTION_VERSION.to_bytes(2, "big"),
            context.user_id.bytes,
            context.key_id.bytes,
            _length_prefix(context.algorithm.encode("ascii")),
            context.key_version.to_bytes(4, "big"),
        )
    )


class SecretProtectionService:
    algorithm_id = PRIVATE_KEY_PROTECTION_ALGORITHM

    def __init__(self, master_key: bytes, aes: AESService) -> None:
        if len(master_key) != 32:
            raise ValueError("The application master key must be exactly 32 bytes")
        self._master_key = master_key
        self._aes = aes

    def protect(self, secret: bytes, context: SecretContext) -> AeadCiphertext:
        if not secret:
            raise ValueError("Secret must not be empty")
        return self._aes.encrypt(
            secret,
            self._master_key,
            encode_private_key_aad(context),
        )

    def unprotect(
        self,
        protected_secret: bytes,
        nonce: bytes,
        context: SecretContext,
    ) -> bytes:
        try:
            return self._aes.decrypt(
                protected_secret,
                self._master_key,
                nonce,
                encode_private_key_aad(context),
            )
        except (InvalidTag, ValueError) as exc:
            raise SecretProtectionError from exc
