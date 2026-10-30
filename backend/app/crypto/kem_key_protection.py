"""ML-KEM + HKDF + AES-GCM protection for per-file AES keys."""

import os
from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag

from app.crypto.aead import AEADProvider
from app.crypto.kdf import KDFProvider
from app.crypto.kem.registry import KEMRegistry, UnsupportedKEMAlgorithmError
from app.crypto.key_wrap import AESGCMKeyWrapProvider, KeyWrapProvider
from app.crypto.identifiers import AES_256_GCM, KEK_AES_256_GCM


PQ_CRYPTO_VERSION = 2
PQ_AAD_VERSION = 2
PQ_KEY_WRAP_ALGORITHM = KEK_AES_256_GCM
_KDF_DOMAIN = b"QuantumShield/FileKeyDerivation/v2"
_WRAP_DOMAIN = b"QuantumShield/FileKeyWrap/v2"


class KEMKeyProtectionError(ValueError):
    """Raised when a Phase 5 file key cannot be recovered safely."""


@dataclass(frozen=True)
class KEMFileContext:
    file_id: UUID
    owner_id: UUID
    recipient_key_id: UUID
    recipient_key_version: int
    kem_algorithm: str
    plaintext_size: int
    crypto_version: int = PQ_CRYPTO_VERSION
    aad_version: int = PQ_AAD_VERSION


@dataclass(frozen=True)
class ProtectedFileKey:
    wrapped_file_key: bytes
    key_wrap_nonce: bytes
    kem_ciphertext: bytes
    kdf_salt: bytes
    kem_algorithm: str
    kdf_algorithm: str
    key_wrap_algorithm: str = PQ_KEY_WRAP_ALGORITHM


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def _encode_context(domain: bytes, context: KEMFileContext) -> bytes:
    if context.plaintext_size < 0 or context.recipient_key_version < 1:
        raise ValueError("Invalid KEM file context")
    return b"".join(
        (
            _length_prefix(domain),
            context.crypto_version.to_bytes(2, "big"),
            context.aad_version.to_bytes(2, "big"),
            context.file_id.bytes,
            context.owner_id.bytes,
            context.recipient_key_id.bytes,
            context.recipient_key_version.to_bytes(4, "big"),
            _length_prefix(context.kem_algorithm.encode("ascii")),
            context.plaintext_size.to_bytes(8, "big"),
        )
    )


class MLKEMFileKeyProtector:
    def __init__(
        self,
        registry: KEMRegistry,
        kdf: KDFProvider,
        key_wrap: KeyWrapProvider | AEADProvider,
    ) -> None:
        self.registry = registry
        self.kdf = kdf
        self.key_wrap = (
            AESGCMKeyWrapProvider(key_wrap)
            if key_wrap.algorithm_id == AES_256_GCM
            else key_wrap
        )

    def protect(
        self,
        file_key: bytes,
        recipient_public_key: bytes,
        context: KEMFileContext,
    ) -> ProtectedFileKey:
        provider = self.registry.get(context.kem_algorithm)
        encapsulated = provider.encapsulate(recipient_public_key)
        shared_secret = encapsulated.shared_secret
        kek = b""
        try:
            salt = os.urandom(self.kdf.salt_size)
            kek = self.kdf.derive(
                shared_secret,
                salt=salt,
                info=_encode_context(_KDF_DOMAIN, context),
            )
            wrapped = self.key_wrap.wrap_key(
                file_key,
                kek,
                _encode_context(_WRAP_DOMAIN, context),
            )
            return ProtectedFileKey(
                wrapped_file_key=wrapped.ciphertext,
                key_wrap_nonce=wrapped.nonce,
                kem_ciphertext=encapsulated.ciphertext,
                kdf_salt=salt,
                kem_algorithm=provider.algorithm_id,
                kdf_algorithm=self.kdf.algorithm_id,
                key_wrap_algorithm=self.key_wrap.algorithm_id,
            )
        finally:
            shared_secret = b""
            kek = b""

    def recover(
        self,
        *,
        recipient_private_key: bytes,
        kem_ciphertext: bytes,
        kdf_salt: bytes,
        wrapped_file_key: bytes,
        key_wrap_nonce: bytes,
        kdf_algorithm: str,
        key_wrap_algorithm: str,
        context: KEMFileContext,
    ) -> bytes:
        if (
            context.crypto_version != PQ_CRYPTO_VERSION
            or context.aad_version != PQ_AAD_VERSION
            or kdf_algorithm != self.kdf.algorithm_id
            or key_wrap_algorithm != self.key_wrap.algorithm_id
        ):
            raise KEMKeyProtectionError

        shared_secret = b""
        kek = b""
        try:
            provider = self.registry.get(context.kem_algorithm)
            shared_secret = provider.decapsulate(
                recipient_private_key,
                kem_ciphertext,
            )
            kek = self.kdf.derive(
                shared_secret,
                salt=kdf_salt,
                info=_encode_context(_KDF_DOMAIN, context),
            )
            return self.key_wrap.unwrap_key(
                wrapped_file_key,
                kek,
                key_wrap_nonce,
                _encode_context(_WRAP_DOMAIN, context),
            )
        except (
            InvalidTag,
            ValueError,
            UnsupportedKEMAlgorithmError,
        ) as exc:
            raise KEMKeyProtectionError from exc
        finally:
            shared_secret = b""
            kek = b""
