"""Versioned file encryption orchestration and deterministic AAD encoding."""

from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag

from app.crypto.aead import AEADProvider
from app.crypto.kem_key_protection import (
    KEMFileContext,
    KEMKeyProtectionError,
    MLKEMFileKeyProtector,
    PQ_AAD_VERSION,
    PQ_CRYPTO_VERSION,
)
from app.crypto.key_protection import MasterKeyWrapper
from app.crypto.identifiers import AES_256_GCM, MASTER_AES_256_GCM
from app.crypto.security_levels import SecurityLevel
from app.crypto.suite_key_protection import (
    SUITE_AAD_VERSION,
    SUITE_CRYPTO_VERSION,
    SuiteFileKeyContext,
    SuiteFileKeyProtector,
    SuiteKeyProtectionError,
)
from app.crypto.suites import CryptoSuiteRegistry
from app.crypto.suites import SecurityArchitecture
from app.crypto.hybrid_key_protection import (
    HybridContext, HybridKeyProtector, HYBRID_FILE_VERSION, HYBRID_FILE_AAD_VERSION,
    HYBRID_COMBINER_VERSION,
)


CRYPTO_VERSION = 1
AAD_VERSION = 1
CONTENT_ALGORITHM = AES_256_GCM
KEY_WRAP_ALGORITHM = MASTER_AES_256_GCM
_CONTENT_DOMAIN = b"QuantumShield/FileContent/v1"
_WRAP_DOMAIN = b"QuantumShield/FileKeyWrap/v1"
_PQ_CONTENT_DOMAIN = b"QuantumShield/FileContent/v2"
_SUITE_CONTENT_DOMAIN = b"QuantumShield/FileContent/v3"
_HYBRID_CONTENT_DOMAIN = b"QuantumShield/FileContent/v4"


class CryptoIntegrityError(ValueError):
    """Raised when authenticated decryption cannot validate its inputs."""


class UnsupportedCryptoMetadataError(ValueError):
    """Raised for an unknown or structurally invalid crypto record."""


@dataclass(frozen=True)
class CryptoContext:
    file_id: UUID
    owner_id: UUID
    plaintext_size: int
    crypto_version: int = CRYPTO_VERSION
    aad_version: int = AAD_VERSION


@dataclass(frozen=True)
class EncryptedFile:
    ciphertext: bytes
    content_nonce: bytes
    wrapped_file_key: bytes
    key_wrap_nonce: bytes
    content_algorithm: str = CONTENT_ALGORITHM
    key_wrap_algorithm: str = KEY_WRAP_ALGORITHM
    crypto_version: int = CRYPTO_VERSION
    aad_version: int = AAD_VERSION
    kem_algorithm: str | None = None
    kem_ciphertext: bytes | None = None
    kdf_algorithm: str | None = None
    kdf_salt: bytes | None = None
    recipient_key_id: UUID | None = None
    recipient_key_version: int | None = None
    crypto_suite_id: str | None = None
    crypto_suite_version: int | None = None
    security_architecture: str = "PQ_ONLY"
    classical_algorithm: str | None = None
    ephemeral_public_key: bytes | None = None
    recipient_classical_key_id: UUID | None = None
    recipient_classical_key_version: int | None = None
    combiner_version: int | None = None


def encode_aad(domain: bytes, context: CryptoContext) -> bytes:
    if context.plaintext_size < 0:
        raise ValueError("Plaintext size cannot be negative")
    return b"".join(
        (
            len(domain).to_bytes(2, "big"),
            domain,
            context.crypto_version.to_bytes(2, "big"),
            context.aad_version.to_bytes(2, "big"),
            context.file_id.bytes,
            context.owner_id.bytes,
            context.plaintext_size.to_bytes(8, "big"),
        )
    )


class EncryptionService:
    def __init__(
        self,
        aes: AEADProvider,
        key_wrapper: MasterKeyWrapper,
        pq_key_protector: MLKEMFileKeyProtector | None = None,
        suite_registry: CryptoSuiteRegistry | None = None,
        suite_key_protector: SuiteFileKeyProtector | None = None,
        hybrid_key_protector: HybridKeyProtector | None = None,
    ) -> None:
        self.aes = aes
        self.key_wrapper = key_wrapper
        self.pq_key_protector = pq_key_protector
        self.suite_registry = suite_registry
        self.suite_key_protector = suite_key_protector
        self.hybrid_key_protector = hybrid_key_protector

    def encrypt_file_for_hybrid_suite(
        self, plaintext: bytes, context: CryptoContext, *, recipient_key_id: UUID,
        recipient_key_version: int, recipient_public_key: bytes,
        recipient_classical_key_id: UUID, recipient_classical_key_version: int,
        recipient_classical_public_key: bytes, crypto_suite_id: str,
        security_level: SecurityLevel,
    ) -> EncryptedFile:
        if (self.suite_registry is None or self.hybrid_key_protector is None
            or context.crypto_version != HYBRID_FILE_VERSION
            or context.aad_version != HYBRID_FILE_AAD_VERSION):
            raise UnsupportedCryptoMetadataError
        suite = self.suite_registry.get_suite(crypto_suite_id, for_encryption=True)
        if suite.architecture is not SecurityArchitecture.HYBRID or suite.security_level is not security_level:
            raise UnsupportedCryptoMetadataError
        hybrid_context = HybridContext(
            purpose="OWNER", file_id=context.file_id, owner_id=context.owner_id,
            recipient_id=context.owner_id, recipient_kem_key_id=recipient_key_id,
            recipient_kem_key_version=recipient_key_version,
            recipient_classical_key_id=recipient_classical_key_id,
            recipient_classical_key_version=recipient_classical_key_version,
            suite_id=suite.suite_id, suite_version=suite.version,
            security_level=security_level.value, plaintext_size=context.plaintext_size,
            crypto_version=context.crypto_version, aad_version=context.aad_version,
        )
        file_key = suite.content_aead.generate_key()
        try:
            content = suite.content_aead.encrypt(plaintext, file_key, encode_aad(_HYBRID_CONTENT_DOMAIN, context))
            protected = self.hybrid_key_protector.protect(
                file_key, recipient_public_key, recipient_classical_public_key, hybrid_context)
            return EncryptedFile(
                ciphertext=content.ciphertext, content_nonce=content.nonce,
                wrapped_file_key=protected.wrapped_file_key, key_wrap_nonce=protected.key_wrap_nonce,
                content_algorithm=suite.content_algorithm, key_wrap_algorithm=suite.key_wrap_algorithm,
                crypto_version=HYBRID_FILE_VERSION, aad_version=HYBRID_FILE_AAD_VERSION,
                kem_algorithm=suite.kem_algorithm, kem_ciphertext=protected.kem_ciphertext,
                kdf_algorithm=suite.kdf_algorithm, kdf_salt=protected.kdf_salt,
                recipient_key_id=recipient_key_id, recipient_key_version=recipient_key_version,
                crypto_suite_id=suite.suite_id, crypto_suite_version=suite.version,
                security_architecture=SecurityArchitecture.HYBRID.value,
                classical_algorithm=suite.classical_algorithm,
                ephemeral_public_key=protected.ephemeral_public_key,
                recipient_classical_key_id=recipient_classical_key_id,
                recipient_classical_key_version=recipient_classical_key_version,
                combiner_version=HYBRID_COMBINER_VERSION,
            )
        finally:
            file_key = b""

    def recover_file_key_v4(self, *, recipient_private_key: bytes,
        classical_private_key: bytes, classical_public_key: bytes,
        wrapped_file_key: bytes, key_wrap_nonce: bytes, kem_ciphertext: bytes,
        kdf_salt: bytes, recipient_key_id: UUID, recipient_key_version: int,
        recipient_classical_key_id: UUID, recipient_classical_key_version: int,
        ephemeral_public_key: bytes, crypto_suite_id: str, crypto_suite_version: int,
        security_level: SecurityLevel, crypto_version: int, aad_version: int,
        context: CryptoContext) -> bytes:
        if self.hybrid_key_protector is None or crypto_version != 4 or aad_version != 4:
            raise UnsupportedCryptoMetadataError
        hybrid_context = HybridContext(
            purpose="OWNER", file_id=context.file_id, owner_id=context.owner_id,
            recipient_id=context.owner_id, recipient_kem_key_id=recipient_key_id,
            recipient_kem_key_version=recipient_key_version,
            recipient_classical_key_id=recipient_classical_key_id,
            recipient_classical_key_version=recipient_classical_key_version,
            suite_id=crypto_suite_id, suite_version=crypto_suite_version,
            security_level=security_level.value, plaintext_size=context.plaintext_size,
            crypto_version=crypto_version, aad_version=aad_version,
        )
        try:
            return self.hybrid_key_protector.recover(
                kem_private_key=recipient_private_key, classical_private_key=classical_private_key,
                classical_public_key=classical_public_key, ephemeral_public_key=ephemeral_public_key,
                kem_ciphertext=kem_ciphertext, kdf_salt=kdf_salt,
                wrapped_file_key=wrapped_file_key, key_wrap_nonce=key_wrap_nonce,
                context=hybrid_context)
        except ValueError as exc:
            raise CryptoIntegrityError from exc

    def get_suite_for_new_encryption(self, suite_id: str):
        if self.suite_registry is None:
            raise UnsupportedCryptoMetadataError
        return self.suite_registry.get_suite(suite_id, for_encryption=True)

    def encrypt_file_for_suite(
        self,
        plaintext: bytes,
        context: CryptoContext,
        *,
        recipient_key_id: UUID,
        recipient_key_version: int,
        recipient_public_key: bytes,
        crypto_suite_id: str,
        security_level: SecurityLevel,
    ) -> EncryptedFile:
        if (
            self.suite_registry is None
            or self.suite_key_protector is None
            or context.crypto_version != SUITE_CRYPTO_VERSION
            or context.aad_version != SUITE_AAD_VERSION
        ):
            raise UnsupportedCryptoMetadataError
        suite = self.suite_registry.get_suite(
            crypto_suite_id, for_encryption=True
        )
        if suite.security_level is not security_level or suite.architecture is not SecurityArchitecture.PQ_ONLY:
            raise UnsupportedCryptoMetadataError
        suite_context = SuiteFileKeyContext(
            file_id=context.file_id,
            owner_id=context.owner_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            crypto_suite_id=suite.suite_id,
            crypto_suite_version=suite.version,
            security_level=security_level,
            plaintext_size=context.plaintext_size,
        )
        file_key = suite.content_aead.generate_key()
        try:
            content = suite.content_aead.encrypt(
                plaintext,
                file_key,
                encode_aad(_SUITE_CONTENT_DOMAIN, context),
            )
            protected = self.suite_key_protector.protect(
                file_key, recipient_public_key, suite_context
            )
            return EncryptedFile(
                ciphertext=content.ciphertext,
                content_nonce=content.nonce,
                wrapped_file_key=protected.wrapped_file_key,
                key_wrap_nonce=protected.key_wrap_nonce,
                content_algorithm=suite.content_algorithm,
                key_wrap_algorithm=protected.key_wrap_algorithm,
                crypto_version=SUITE_CRYPTO_VERSION,
                aad_version=SUITE_AAD_VERSION,
                kem_algorithm=protected.kem_algorithm,
                kem_ciphertext=protected.kem_ciphertext,
                kdf_algorithm=protected.kdf_algorithm,
                kdf_salt=protected.kdf_salt,
                recipient_key_id=recipient_key_id,
                recipient_key_version=recipient_key_version,
                crypto_suite_id=suite.suite_id,
                crypto_suite_version=suite.version,
            )
        finally:
            file_key = b""

    def encrypt_file(self, plaintext: bytes, context: CryptoContext) -> EncryptedFile:
        file_key = self.aes.generate_key()
        try:
            content = self.aes.encrypt(
                plaintext,
                file_key,
                encode_aad(_CONTENT_DOMAIN, context),
            )
            wrapped = self.key_wrapper.wrap_key(
                file_key,
                encode_aad(_WRAP_DOMAIN, context),
            )
            return EncryptedFile(
                ciphertext=content.ciphertext,
                content_nonce=content.nonce,
                wrapped_file_key=wrapped.ciphertext,
                key_wrap_nonce=wrapped.nonce,
            )
        finally:
            # Python bytes and library copies cannot be guaranteed zeroized.
            file_key = b""

    def encrypt_file_for_recipient(
        self,
        plaintext: bytes,
        context: CryptoContext,
        *,
        recipient_key_id: UUID,
        recipient_key_version: int,
        recipient_public_key: bytes,
        kem_algorithm: str,
    ) -> EncryptedFile:
        if (
            self.pq_key_protector is None
            or context.crypto_version != PQ_CRYPTO_VERSION
            or context.aad_version != PQ_AAD_VERSION
        ):
            raise UnsupportedCryptoMetadataError

        kem_context = KEMFileContext(
            file_id=context.file_id,
            owner_id=context.owner_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            kem_algorithm=kem_algorithm,
            plaintext_size=context.plaintext_size,
            crypto_version=context.crypto_version,
            aad_version=context.aad_version,
        )
        file_key = self.aes.generate_key()
        try:
            content = self.aes.encrypt(
                plaintext,
                file_key,
                encode_aad(_PQ_CONTENT_DOMAIN, context),
            )
            protected = self.pq_key_protector.protect(
                file_key,
                recipient_public_key,
                kem_context,
            )
            return EncryptedFile(
                ciphertext=content.ciphertext,
                content_nonce=content.nonce,
                wrapped_file_key=protected.wrapped_file_key,
                key_wrap_nonce=protected.key_wrap_nonce,
                key_wrap_algorithm=protected.key_wrap_algorithm,
                crypto_version=PQ_CRYPTO_VERSION,
                aad_version=PQ_AAD_VERSION,
                kem_algorithm=protected.kem_algorithm,
                kem_ciphertext=protected.kem_ciphertext,
                kdf_algorithm=protected.kdf_algorithm,
                kdf_salt=protected.kdf_salt,
                recipient_key_id=recipient_key_id,
                recipient_key_version=recipient_key_version,
            )
        finally:
            file_key = b""

    def decrypt_file(
        self,
        ciphertext: bytes,
        *,
        content_nonce: bytes,
        wrapped_file_key: bytes,
        key_wrap_nonce: bytes,
        content_algorithm: str,
        key_wrap_algorithm: str,
        crypto_version: int,
        aad_version: int,
        context: CryptoContext,
    ) -> bytes:
        if (
            content_algorithm != CONTENT_ALGORITHM
            or key_wrap_algorithm != KEY_WRAP_ALGORITHM
            or crypto_version != CRYPTO_VERSION
            or aad_version != AAD_VERSION
            or context.crypto_version != crypto_version
            or context.aad_version != aad_version
        ):
            raise UnsupportedCryptoMetadataError

        file_key = b""
        try:
            file_key = self.key_wrapper.unwrap_key(
                wrapped_file_key,
                key_wrap_nonce,
                encode_aad(_WRAP_DOMAIN, context),
            )
            return self.aes.decrypt(
                ciphertext,
                file_key,
                content_nonce,
                encode_aad(_CONTENT_DOMAIN, context),
            )
        except (InvalidTag, ValueError) as exc:
            raise CryptoIntegrityError from exc
        finally:
            file_key = b""

    def recover_file_key(
        self,
        *,
        wrapped_file_key: bytes,
        key_wrap_nonce: bytes,
        content_algorithm: str,
        key_wrap_algorithm: str,
        crypto_version: int,
        aad_version: int,
        context: CryptoContext,
    ) -> bytes:
        """Recover a legacy file key without reading or decrypting file content."""

        if (
            content_algorithm != CONTENT_ALGORITHM
            or key_wrap_algorithm != KEY_WRAP_ALGORITHM
            or crypto_version != CRYPTO_VERSION
            or aad_version != AAD_VERSION
            or context.crypto_version != crypto_version
            or context.aad_version != aad_version
        ):
            raise UnsupportedCryptoMetadataError
        try:
            return self.key_wrapper.unwrap_key(
                wrapped_file_key,
                key_wrap_nonce,
                encode_aad(_WRAP_DOMAIN, context),
            )
        except (InvalidTag, ValueError) as exc:
            raise CryptoIntegrityError from exc

    def recover_file_key_v2(
        self,
        *,
        recipient_private_key: bytes,
        wrapped_file_key: bytes,
        key_wrap_nonce: bytes,
        content_algorithm: str,
        key_wrap_algorithm: str,
        kem_algorithm: str,
        kem_ciphertext: bytes,
        kdf_algorithm: str,
        kdf_salt: bytes,
        recipient_key_id: UUID,
        recipient_key_version: int,
        crypto_version: int,
        aad_version: int,
        context: CryptoContext,
    ) -> bytes:
        """Recover a Phase 5 file key without decrypting the stored object."""

        if (
            self.pq_key_protector is None
            or content_algorithm != CONTENT_ALGORITHM
            or crypto_version != PQ_CRYPTO_VERSION
            or aad_version != PQ_AAD_VERSION
            or context.crypto_version != crypto_version
            or context.aad_version != aad_version
        ):
            raise UnsupportedCryptoMetadataError
        kem_context = KEMFileContext(
            file_id=context.file_id,
            owner_id=context.owner_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            kem_algorithm=kem_algorithm,
            plaintext_size=context.plaintext_size,
            crypto_version=crypto_version,
            aad_version=aad_version,
        )
        try:
            return self.pq_key_protector.recover(
                recipient_private_key=recipient_private_key,
                kem_ciphertext=kem_ciphertext,
                kdf_salt=kdf_salt,
                wrapped_file_key=wrapped_file_key,
                key_wrap_nonce=key_wrap_nonce,
                kdf_algorithm=kdf_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
                context=kem_context,
            )
        except (ValueError, KEMKeyProtectionError) as exc:
            raise CryptoIntegrityError from exc

    def decrypt_content(
        self,
        ciphertext: bytes,
        *,
        file_key: bytes,
        content_nonce: bytes,
        content_algorithm: str,
        crypto_version: int,
        aad_version: int,
        context: CryptoContext,
        crypto_suite_id: str | None = None,
        crypto_suite_version: int | None = None,
        security_level: SecurityLevel | None = None,
        kem_algorithm: str | None = None,
        kdf_algorithm: str | None = None,
        key_wrap_algorithm: str | None = None,
        security_architecture: SecurityArchitecture | str = SecurityArchitecture.PQ_ONLY,
        classical_algorithm: str | None = None,
    ) -> bytes:
        """Decrypt file content with a key recovered from any authorized envelope."""

        if (
            context.crypto_version != crypto_version
            or context.aad_version != aad_version
        ):
            raise UnsupportedCryptoMetadataError
        content_provider = self.aes
        if crypto_version == CRYPTO_VERSION and aad_version == AAD_VERSION:
            if content_algorithm != CONTENT_ALGORITHM:
                raise UnsupportedCryptoMetadataError
            domain = _CONTENT_DOMAIN
        elif crypto_version == PQ_CRYPTO_VERSION and aad_version == PQ_AAD_VERSION:
            if content_algorithm != CONTENT_ALGORITHM:
                raise UnsupportedCryptoMetadataError
            domain = _PQ_CONTENT_DOMAIN
        elif (
            ((crypto_version == SUITE_CRYPTO_VERSION and aad_version == SUITE_AAD_VERSION)
             or (crypto_version == HYBRID_FILE_VERSION and aad_version == HYBRID_FILE_AAD_VERSION))
            and self.suite_registry is not None
            and crypto_suite_id is not None
            and crypto_suite_version is not None
            and security_level is not None
            and kem_algorithm is not None
            and kdf_algorithm is not None
            and key_wrap_algorithm is not None
        ):
            suite = self.suite_registry.validate_metadata(
                suite_id=crypto_suite_id,
                suite_version=crypto_suite_version,
                security_level=security_level,
                content_algorithm=content_algorithm,
                kem_algorithm=kem_algorithm,
                kdf_algorithm=kdf_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
                architecture=security_architecture,
                classical_algorithm=classical_algorithm,
            )
            content_provider = suite.content_aead
            domain = _HYBRID_CONTENT_DOMAIN if crypto_version == HYBRID_FILE_VERSION else _SUITE_CONTENT_DOMAIN
        else:
            raise UnsupportedCryptoMetadataError
        try:
            return content_provider.decrypt(
                ciphertext,
                file_key,
                content_nonce,
                encode_aad(domain, context),
            )
        except (InvalidTag, ValueError) as exc:
            raise CryptoIntegrityError from exc

    def decrypt_file_v2(
        self,
        ciphertext: bytes,
        *,
        recipient_private_key: bytes,
        content_nonce: bytes,
        wrapped_file_key: bytes,
        key_wrap_nonce: bytes,
        content_algorithm: str,
        key_wrap_algorithm: str,
        kem_algorithm: str,
        kem_ciphertext: bytes,
        kdf_algorithm: str,
        kdf_salt: bytes,
        recipient_key_id: UUID,
        recipient_key_version: int,
        crypto_version: int,
        aad_version: int,
        context: CryptoContext,
    ) -> bytes:
        if (
            self.pq_key_protector is None
            or content_algorithm != CONTENT_ALGORITHM
            or crypto_version != PQ_CRYPTO_VERSION
            or aad_version != PQ_AAD_VERSION
            or context.crypto_version != crypto_version
            or context.aad_version != aad_version
        ):
            raise UnsupportedCryptoMetadataError

        kem_context = KEMFileContext(
            file_id=context.file_id,
            owner_id=context.owner_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            kem_algorithm=kem_algorithm,
            plaintext_size=context.plaintext_size,
            crypto_version=crypto_version,
            aad_version=aad_version,
        )
        file_key = b""
        try:
            file_key = self.pq_key_protector.recover(
                recipient_private_key=recipient_private_key,
                kem_ciphertext=kem_ciphertext,
                kdf_salt=kdf_salt,
                wrapped_file_key=wrapped_file_key,
                key_wrap_nonce=key_wrap_nonce,
                kdf_algorithm=kdf_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
                context=kem_context,
            )
            return self.aes.decrypt(
                ciphertext,
                file_key,
                content_nonce,
                encode_aad(_PQ_CONTENT_DOMAIN, context),
            )
        except (InvalidTag, ValueError, KEMKeyProtectionError) as exc:
            raise CryptoIntegrityError from exc
        finally:
            file_key = b""

    def recover_file_key_v3(
        self,
        *,
        recipient_private_key: bytes,
        wrapped_file_key: bytes,
        key_wrap_nonce: bytes,
        content_algorithm: str,
        key_wrap_algorithm: str,
        kem_algorithm: str,
        kem_ciphertext: bytes,
        kdf_algorithm: str,
        kdf_salt: bytes,
        recipient_key_id: UUID,
        recipient_key_version: int,
        crypto_suite_id: str,
        crypto_suite_version: int,
        security_level: SecurityLevel,
        crypto_version: int,
        aad_version: int,
        context: CryptoContext,
    ) -> bytes:
        if (
            self.suite_key_protector is None
            or crypto_version != SUITE_CRYPTO_VERSION
            or aad_version != SUITE_AAD_VERSION
            or context.crypto_version != crypto_version
            or context.aad_version != aad_version
        ):
            raise UnsupportedCryptoMetadataError
        suite_context = SuiteFileKeyContext(
            file_id=context.file_id,
            owner_id=context.owner_id,
            recipient_key_id=recipient_key_id,
            recipient_key_version=recipient_key_version,
            crypto_suite_id=crypto_suite_id,
            crypto_suite_version=crypto_suite_version,
            security_level=security_level,
            plaintext_size=context.plaintext_size,
            crypto_version=crypto_version,
            aad_version=aad_version,
        )
        try:
            return self.suite_key_protector.recover(
                recipient_private_key=recipient_private_key,
                kem_ciphertext=kem_ciphertext,
                kdf_salt=kdf_salt,
                wrapped_file_key=wrapped_file_key,
                key_wrap_nonce=key_wrap_nonce,
                kem_algorithm=kem_algorithm,
                kdf_algorithm=kdf_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
                content_algorithm=content_algorithm,
                context=suite_context,
            )
        except (ValueError, SuiteKeyProtectionError) as exc:
            raise CryptoIntegrityError from exc

    def decrypt_file_v3(
        self,
        ciphertext: bytes,
        *,
        recipient_private_key: bytes,
        content_nonce: bytes,
        wrapped_file_key: bytes,
        key_wrap_nonce: bytes,
        content_algorithm: str,
        key_wrap_algorithm: str,
        kem_algorithm: str,
        kem_ciphertext: bytes,
        kdf_algorithm: str,
        kdf_salt: bytes,
        recipient_key_id: UUID,
        recipient_key_version: int,
        crypto_suite_id: str,
        crypto_suite_version: int,
        security_level: SecurityLevel,
        crypto_version: int,
        aad_version: int,
        context: CryptoContext,
    ) -> bytes:
        file_key = b""
        try:
            file_key = self.recover_file_key_v3(
                recipient_private_key=recipient_private_key,
                wrapped_file_key=wrapped_file_key,
                key_wrap_nonce=key_wrap_nonce,
                content_algorithm=content_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
                kem_algorithm=kem_algorithm,
                kem_ciphertext=kem_ciphertext,
                kdf_algorithm=kdf_algorithm,
                kdf_salt=kdf_salt,
                recipient_key_id=recipient_key_id,
                recipient_key_version=recipient_key_version,
                crypto_suite_id=crypto_suite_id,
                crypto_suite_version=crypto_suite_version,
                security_level=security_level,
                crypto_version=crypto_version,
                aad_version=aad_version,
                context=context,
            )
            return self.decrypt_content(
                ciphertext,
                file_key=file_key,
                content_nonce=content_nonce,
                content_algorithm=content_algorithm,
                crypto_version=crypto_version,
                aad_version=aad_version,
                context=context,
                crypto_suite_id=crypto_suite_id,
                crypto_suite_version=crypto_suite_version,
                security_level=security_level,
                kem_algorithm=kem_algorithm,
                kdf_algorithm=kdf_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
            )
        finally:
            file_key = b""
