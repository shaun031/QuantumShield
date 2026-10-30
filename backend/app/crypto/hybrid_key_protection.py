"""Versioned X25519 + ML-KEM envelope protection.

The project-specific transcript is bound to both HKDF info and wrap AAD. This is
not the TLS hybrid key schedule; RFC 10024's TLS transcript assumptions do not
apply to stored-file envelopes.
"""

import os
from dataclasses import dataclass
from uuid import UUID

from cryptography.exceptions import InvalidTag

from app.crypto.identifiers import X25519
from app.crypto.key_agreement import KeyAgreementProvider
from app.crypto.kdf import KDFProvider
from app.crypto.suites import CryptoSuiteRegistry, SecurityArchitecture


HYBRID_FILE_VERSION = 4
HYBRID_FILE_AAD_VERSION = 4
HYBRID_SHARE_VERSION = 3
HYBRID_SHARE_AAD_VERSION = 3
HYBRID_COMBINER_VERSION = 1
_DOMAIN = b"QuantumShield/HybridEnvelope/v1"


def _field(value: bytes) -> bytes:
    if len(value) > 65535:
        raise ValueError("Hybrid context field too long")
    return len(value).to_bytes(2, "big") + value


@dataclass(frozen=True)
class HybridContext:
    purpose: str
    file_id: UUID
    owner_id: UUID
    recipient_id: UUID
    recipient_kem_key_id: UUID
    recipient_kem_key_version: int
    recipient_classical_key_id: UUID
    recipient_classical_key_version: int
    suite_id: str
    suite_version: int
    security_level: str
    plaintext_size: int
    crypto_version: int
    aad_version: int
    share_id: UUID | None = None
    combiner_version: int = HYBRID_COMBINER_VERSION

    def encode(self, domain: bytes, ephemeral_public_key: bytes, recipient_public_key: bytes) -> bytes:
        if (
            self.purpose not in {"OWNER", "SHARE"}
            or self.combiner_version != HYBRID_COMBINER_VERSION
            or self.plaintext_size < 0
            or self.recipient_kem_key_version < 1
            or self.recipient_classical_key_version < 1
            or len(ephemeral_public_key) != 32
            or len(recipient_public_key) != 32
            or (self.purpose == "SHARE") != (self.share_id is not None)
        ):
            raise ValueError("Invalid hybrid envelope context")
        return b"".join((
            _field(_DOMAIN), _field(domain), _field(self.purpose.encode("ascii")),
            self.crypto_version.to_bytes(2, "big"), self.aad_version.to_bytes(2, "big"),
            self.combiner_version.to_bytes(2, "big"), self.suite_version.to_bytes(2, "big"),
            _field(self.suite_id.encode("ascii")), _field(self.security_level.encode("ascii")),
            _field(SecurityArchitecture.HYBRID.value.encode("ascii")), _field(X25519.encode("ascii")),
            self.file_id.bytes, self.owner_id.bytes, self.recipient_id.bytes,
            (self.share_id.bytes if self.share_id else bytes(16)),
            self.recipient_kem_key_id.bytes, self.recipient_kem_key_version.to_bytes(4, "big"),
            self.recipient_classical_key_id.bytes, self.recipient_classical_key_version.to_bytes(4, "big"),
            self.plaintext_size.to_bytes(8, "big"), ephemeral_public_key, recipient_public_key,
        ))


@dataclass(frozen=True)
class ProtectedHybridKey:
    wrapped_file_key: bytes
    key_wrap_nonce: bytes
    kem_ciphertext: bytes
    kdf_salt: bytes
    ephemeral_public_key: bytes


class HybridSecretCombiner:
    """Length-delimited PQ-then-classical input to suite-selected HKDF-SHA256."""

    @staticmethod
    def derive(kdf: KDFProvider, pq_secret: bytes, classical_secret: bytes,
               *, salt: bytes, info: bytes) -> bytes:
        if len(pq_secret) != 32 or len(classical_secret) != 32 or len(salt) != kdf.salt_size:
            raise ValueError("Invalid hybrid component or salt length")
        return kdf.derive(_field(pq_secret) + _field(classical_secret), salt=salt, info=info)


class HybridKeyProtector:
    def __init__(self, suites: CryptoSuiteRegistry, agreement: KeyAgreementProvider) -> None:
        self.suites = suites
        self.agreement = agreement

    def _suite(self, context: HybridContext, *, encrypt: bool):
        suite = self.suites.get_suite(context.suite_id, for_encryption=encrypt)
        if (suite.architecture is not SecurityArchitecture.HYBRID
            or suite.classical_algorithm != X25519
            or self.agreement.algorithm_id != suite.classical_algorithm
            or self.agreement.public_key_size != 32
            or self.agreement.shared_secret_size != 32
            or suite.version != context.suite_version
            or suite.security_level.value != context.security_level):
            raise ValueError("Hybrid context does not match suite")
        return suite

    def protect(self, file_key: bytes, kem_public_key: bytes,
                classical_public_key: bytes, context: HybridContext) -> ProtectedHybridKey:
        suite = self._suite(context, encrypt=True)
        if len(classical_public_key) != 32:
            raise ValueError("Invalid recipient X25519 public key")
        ephemeral = self.agreement.generate_keypair()
        encapsulated = suite.kem.encapsulate(kem_public_key)
        classical_secret = self.agreement.derive_shared_secret(ephemeral.private_key, classical_public_key)
        salt = os.urandom(suite.kdf.salt_size)
        info = context.encode(b"HKDF", ephemeral.public_key, classical_public_key)
        aad = context.encode(b"AES-GCM-WRAP", ephemeral.public_key, classical_public_key)
        kek = HybridSecretCombiner.derive(suite.kdf, encapsulated.shared_secret, classical_secret, salt=salt, info=info)
        wrapped = suite.key_wrap.wrap_key(file_key, kek, aad)
        return ProtectedHybridKey(wrapped.ciphertext, wrapped.nonce, encapsulated.ciphertext, salt, ephemeral.public_key)

    def recover(self, *, kem_private_key: bytes, classical_private_key: bytes,
                classical_public_key: bytes, ephemeral_public_key: bytes,
                kem_ciphertext: bytes, kdf_salt: bytes, wrapped_file_key: bytes,
                key_wrap_nonce: bytes, context: HybridContext) -> bytes:
        try:
            suite = self._suite(context, encrypt=False)
            if len(kdf_salt) != suite.kdf.salt_size:
                raise ValueError("Invalid hybrid salt")
            # Private/public correspondence is checked, so a substituted stored
            # recipient public key cannot redefine the transcript.
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import x25519
            actual_public = x25519.X25519PrivateKey.from_private_bytes(classical_private_key).public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            if actual_public != classical_public_key:
                raise ValueError("Mismatched X25519 key pair")
            pq_secret = suite.kem.decapsulate(kem_private_key, kem_ciphertext)
            classical_secret = self.agreement.derive_shared_secret(classical_private_key, ephemeral_public_key)
            info = context.encode(b"HKDF", ephemeral_public_key, classical_public_key)
            aad = context.encode(b"AES-GCM-WRAP", ephemeral_public_key, classical_public_key)
            kek = HybridSecretCombiner.derive(suite.kdf, pq_secret, classical_secret, salt=kdf_salt, info=info)
            return suite.key_wrap.unwrap_key(wrapped_file_key, kek, key_wrap_nonce, aad)
        except (InvalidTag, ValueError) as exc:
            raise ValueError("Hybrid envelope authentication failed") from exc
