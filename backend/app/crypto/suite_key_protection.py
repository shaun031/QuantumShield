"""Suite-driven owner and recipient file-key envelope protection."""

import os
from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag

from app.crypto.kem_key_protection import ProtectedFileKey
from app.crypto.security_levels import SecurityLevel
from app.crypto.suites import (
    CryptoSuiteMismatchError,
    CryptoSuiteRegistry,
    UnsupportedCryptoSuiteError,
    SecurityArchitecture,
)


SUITE_CRYPTO_VERSION = 3
SUITE_AAD_VERSION = 3
SUITE_SHARE_CRYPTO_VERSION = 2
SUITE_SHARE_AAD_VERSION = 2
_FILE_KDF_DOMAIN = b"QuantumShield/SuiteFileKeyDerivation/v3"
_FILE_WRAP_DOMAIN = b"QuantumShield/SuiteFileKeyWrap/v3"
_SHARE_KDF_DOMAIN = b"QuantumShield/SuiteShareKeyDerivation/v2"
_SHARE_WRAP_DOMAIN = b"QuantumShield/SuiteShareKeyWrap/v2"


class SuiteKeyProtectionError(ValueError):
    pass


def _length_prefix(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


@dataclass(frozen=True)
class SuiteFileKeyContext:
    file_id: UUID
    owner_id: UUID
    recipient_key_id: UUID
    recipient_key_version: int
    crypto_suite_id: str
    crypto_suite_version: int
    security_level: SecurityLevel
    plaintext_size: int
    crypto_version: int = SUITE_CRYPTO_VERSION
    aad_version: int = SUITE_AAD_VERSION


@dataclass(frozen=True)
class SuiteShareKeyContext:
    share_id: UUID
    file_id: UUID
    owner_id: UUID
    recipient_id: UUID
    recipient_key_id: UUID
    recipient_key_version: int
    crypto_suite_id: str
    crypto_suite_version: int
    security_level: SecurityLevel
    plaintext_size: int
    crypto_version: int = SUITE_SHARE_CRYPTO_VERSION
    aad_version: int = SUITE_SHARE_AAD_VERSION


def _encode_file_context(domain: bytes, context: SuiteFileKeyContext) -> bytes:
    if context.plaintext_size < 0 or context.recipient_key_version < 1:
        raise ValueError("Invalid suite file-key context")
    return b"".join(
        (
            _length_prefix(domain),
            context.crypto_version.to_bytes(2, "big"),
            context.aad_version.to_bytes(2, "big"),
            context.crypto_suite_version.to_bytes(2, "big"),
            _length_prefix(context.crypto_suite_id.encode("ascii")),
            _length_prefix(context.security_level.value.encode("ascii")),
            context.file_id.bytes,
            context.owner_id.bytes,
            context.recipient_key_id.bytes,
            context.recipient_key_version.to_bytes(4, "big"),
            context.plaintext_size.to_bytes(8, "big"),
        )
    )


def _encode_share_context(domain: bytes, context: SuiteShareKeyContext) -> bytes:
    if context.plaintext_size < 0 or context.recipient_key_version < 1:
        raise ValueError("Invalid suite share-key context")
    return b"".join(
        (
            _length_prefix(domain),
            context.crypto_version.to_bytes(2, "big"),
            context.aad_version.to_bytes(2, "big"),
            context.crypto_suite_version.to_bytes(2, "big"),
            _length_prefix(context.crypto_suite_id.encode("ascii")),
            _length_prefix(context.security_level.value.encode("ascii")),
            context.share_id.bytes,
            context.file_id.bytes,
            context.owner_id.bytes,
            context.recipient_id.bytes,
            context.recipient_key_id.bytes,
            context.recipient_key_version.to_bytes(4, "big"),
            context.plaintext_size.to_bytes(8, "big"),
        )
    )


class SuiteFileKeyProtector:
    def __init__(self, suites: CryptoSuiteRegistry) -> None:
        self.suites = suites

    def _suite(self, context: SuiteFileKeyContext, *, for_encryption: bool):
        suite = self.suites.get_suite(
            context.crypto_suite_id, for_encryption=for_encryption
        )
        if (
            suite.version != context.crypto_suite_version
            or suite.security_level is not context.security_level
            or suite.architecture is not SecurityArchitecture.PQ_ONLY
        ):
            raise CryptoSuiteMismatchError("File-key context does not match suite")
        return suite

    def protect(
        self,
        file_key: bytes,
        recipient_public_key: bytes,
        context: SuiteFileKeyContext,
    ) -> ProtectedFileKey:
        suite = self._suite(context, for_encryption=True)
        encapsulated = suite.kem.encapsulate(recipient_public_key)
        shared_secret = encapsulated.shared_secret
        kek = b""
        try:
            salt = os.urandom(suite.kdf.salt_size)
            kek = suite.kdf.derive(
                shared_secret,
                salt=salt,
                info=_encode_file_context(_FILE_KDF_DOMAIN, context),
            )
            wrapped = suite.key_wrap.wrap_key(
                file_key,
                kek,
                _encode_file_context(_FILE_WRAP_DOMAIN, context),
            )
            return ProtectedFileKey(
                wrapped_file_key=wrapped.ciphertext,
                key_wrap_nonce=wrapped.nonce,
                kem_ciphertext=encapsulated.ciphertext,
                kdf_salt=salt,
                kem_algorithm=suite.kem_algorithm,
                kdf_algorithm=suite.kdf_algorithm,
                key_wrap_algorithm=suite.key_wrap_algorithm,
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
        kem_algorithm: str,
        kdf_algorithm: str,
        key_wrap_algorithm: str,
        content_algorithm: str,
        context: SuiteFileKeyContext,
    ) -> bytes:
        try:
            suite = self.suites.validate_metadata(
                suite_id=context.crypto_suite_id,
                suite_version=context.crypto_suite_version,
                security_level=context.security_level,
                content_algorithm=content_algorithm,
                kem_algorithm=kem_algorithm,
                kdf_algorithm=kdf_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
                architecture=SecurityArchitecture.PQ_ONLY,
            )
            shared_secret = suite.kem.decapsulate(
                recipient_private_key, kem_ciphertext
            )
            kek = suite.kdf.derive(
                shared_secret,
                salt=kdf_salt,
                info=_encode_file_context(_FILE_KDF_DOMAIN, context),
            )
            return suite.key_wrap.unwrap_key(
                wrapped_file_key,
                kek,
                key_wrap_nonce,
                _encode_file_context(_FILE_WRAP_DOMAIN, context),
            )
        except (
            InvalidTag,
            ValueError,
            UnsupportedCryptoSuiteError,
            CryptoSuiteMismatchError,
        ) as exc:
            raise SuiteKeyProtectionError from exc
        finally:
            shared_secret = b""
            kek = b""


class SuiteShareKeyProtector:
    def __init__(self, suites: CryptoSuiteRegistry) -> None:
        self.suites = suites

    def _suite(self, context: SuiteShareKeyContext, *, for_encryption: bool):
        suite = self.suites.get_suite(
            context.crypto_suite_id, for_encryption=for_encryption
        )
        if (
            suite.version != context.crypto_suite_version
            or suite.security_level is not context.security_level
            or suite.architecture is not SecurityArchitecture.PQ_ONLY
        ):
            raise CryptoSuiteMismatchError("Share context does not match suite")
        return suite

    def protect(
        self,
        file_key: bytes,
        recipient_public_key: bytes,
        context: SuiteShareKeyContext,
    ) -> ProtectedFileKey:
        suite = self._suite(context, for_encryption=True)
        encapsulated = suite.kem.encapsulate(recipient_public_key)
        shared_secret = encapsulated.shared_secret
        kek = b""
        try:
            salt = os.urandom(suite.kdf.salt_size)
            kek = suite.kdf.derive(
                shared_secret,
                salt=salt,
                info=_encode_share_context(_SHARE_KDF_DOMAIN, context),
            )
            wrapped = suite.key_wrap.wrap_key(
                file_key,
                kek,
                _encode_share_context(_SHARE_WRAP_DOMAIN, context),
            )
            return ProtectedFileKey(
                wrapped_file_key=wrapped.ciphertext,
                key_wrap_nonce=wrapped.nonce,
                kem_ciphertext=encapsulated.ciphertext,
                kdf_salt=salt,
                kem_algorithm=suite.kem_algorithm,
                kdf_algorithm=suite.kdf_algorithm,
                key_wrap_algorithm=suite.key_wrap_algorithm,
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
        kem_algorithm: str,
        kdf_algorithm: str,
        key_wrap_algorithm: str,
        content_algorithm: str,
        context: SuiteShareKeyContext,
    ) -> bytes:
        try:
            suite = self.suites.validate_metadata(
                suite_id=context.crypto_suite_id,
                suite_version=context.crypto_suite_version,
                security_level=context.security_level,
                content_algorithm=content_algorithm,
                kem_algorithm=kem_algorithm,
                kdf_algorithm=kdf_algorithm,
                key_wrap_algorithm=key_wrap_algorithm,
                architecture=SecurityArchitecture.PQ_ONLY,
            )
            shared_secret = suite.kem.decapsulate(
                recipient_private_key, kem_ciphertext
            )
            kek = suite.kdf.derive(
                shared_secret,
                salt=kdf_salt,
                info=_encode_share_context(_SHARE_KDF_DOMAIN, context),
            )
            return suite.key_wrap.unwrap_key(
                wrapped_file_key,
                kek,
                key_wrap_nonce,
                _encode_share_context(_SHARE_WRAP_DOMAIN, context),
            )
        except (
            InvalidTag,
            ValueError,
            UnsupportedCryptoSuiteError,
            CryptoSuiteMismatchError,
        ) as exc:
            raise SuiteKeyProtectionError from exc
        finally:
            shared_secret = b""
            kek = b""
