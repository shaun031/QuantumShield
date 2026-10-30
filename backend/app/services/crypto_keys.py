"""Idempotent multi-algorithm ML-KEM keyset provisioning and recovery."""

from uuid import UUID, uuid4

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.crypto.kem.registry import KEMRegistry
from app.crypto.key_agreement import X25519Provider
from app.crypto.identifiers import X25519
from app.crypto.key_purpose import KeyPurpose, PURPOSE_BY_ALGORITHM
from app.crypto.signature_profiles import SignatureProfileRegistry, build_signature_profile_registry
from app.crypto.secret_protection import (
    PRIVATE_KEY_PROTECTION_VERSION,
    SecretContext,
    SecretProtectionError,
    SecretProtectionService,
)
from app.models.user import User
from app.models.user_crypto_key import UserCryptoKey
from app.repositories.crypto_key import CryptoKeyRepository


class CryptoKeyAlreadyExistsError(ValueError):
    """Retained for compatibility with callers handling provisioning conflicts."""


class CryptoKeyNotFoundError(LookupError):
    """Raised when an exact requested active public key is unavailable."""


class PrivateKeyUnavailableError(ValueError):
    """Raised when an exact recorded private key cannot be recovered safely."""


class CryptoKeyService:
    def __init__(
        self,
        session: Session,
        registry: KEMRegistry,
        secret_protection: SecretProtectionService,
        default_algorithm: str,
        agreement: X25519Provider | None = None,
        signature_profiles: SignatureProfileRegistry | None = None,
        default_signature_algorithm: str = "ML-DSA-65",
    ) -> None:
        self.session = session
        self.registry = registry
        self.secret_protection = secret_protection
        self.default_algorithm = default_algorithm
        self.agreement = agreement or X25519Provider()
        self.signature_profiles = signature_profiles or build_signature_profile_registry()
        self.default_signature_algorithm = default_signature_algorithm
        self.keys = CryptoKeyRepository(session)

    def _provider(self, algorithm: str):
        if algorithm == X25519:
            return self.agreement
        if PURPOSE_BY_ALGORITHM.get(algorithm) is KeyPurpose.SIGNATURE:
            return self.signature_profiles.for_algorithm(algorithm).provider
        return self.registry.get(algorithm)

    def _create_key(self, user: User, algorithm: str) -> UserCryptoKey:
        provider = self._provider(algorithm)
        keypair = provider.generate_keypair()
        key_id = uuid4()
        key_version = self.keys.next_version(user.id, algorithm)
        context = SecretContext(
            user_id=user.id,
            key_id=key_id,
            algorithm=algorithm,
            key_version=key_version,
        )
        protected = self.secret_protection.protect(keypair.private_key, context)
        record = UserCryptoKey(
            id=key_id,
            user_id=user.id,
            algorithm=algorithm,
            key_purpose=PURPOSE_BY_ALGORITHM[algorithm].value,
            public_key=keypair.public_key,
            encrypted_private_key=protected.ciphertext,
            private_key_nonce=protected.nonce,
            private_key_protection_algorithm=self.secret_protection.algorithm_id,
            private_key_protection_version=PRIVATE_KEY_PROTECTION_VERSION,
            key_version=key_version,
            is_active=True,
        )
        self.keys.add(record)
        self.session.flush()
        return record

    def ensure_keyset_for_user(
        self,
        user: User,
        *,
        commit: bool = True,
    ) -> list[UserCryptoKey]:
        """Create only missing active algorithm keys and return the full keyset."""

        try:
            for algorithm in (*self.registry.enabled_algorithms, X25519, self.default_signature_algorithm):
                if self.keys.get_active(user.id, algorithm) is None:
                    self._create_key(user, algorithm)
            if commit:
                self.session.commit()
            return self.list_active_for_user(user.id)
        except IntegrityError as exc:
            if commit:
                self.session.rollback()
            raise CryptoKeyAlreadyExistsError from exc
        except SQLAlchemyError:
            if commit:
                self.session.rollback()
            raise

    def create_for_user(
        self,
        user: User,
        *,
        commit: bool = True,
    ) -> UserCryptoKey:
        """Compatibility wrapper returning the STANDARD key after keyset ensure."""

        self.ensure_keyset_for_user(user, commit=commit)
        return self.get_active_for_user(user.id, self.default_algorithm)

    def ensure_signing_key_for_user(self, user: User, *, commit: bool = True) -> UserCryptoKey:
        """Idempotently provision only the configured signing identity."""
        key = self.keys.get_active(user.id, self.default_signature_algorithm)
        if key is not None:
            if key.key_purpose != KeyPurpose.SIGNATURE.value:
                raise PrivateKeyUnavailableError
            return key
        try:
            key = self._create_key(user, self.default_signature_algorithm)
            if commit:
                self.session.commit()
            return key
        except SQLAlchemyError:
            if commit:
                self.session.rollback()
            raise

    def list_active_for_user(self, user_id: UUID) -> list[UserCryptoKey]:
        by_algorithm = {key.algorithm: key for key in self.keys.list_active(user_id)}
        return [
            by_algorithm[algorithm]
            for algorithm in (*self.registry.enabled_algorithms, X25519, self.default_signature_algorithm)
            if algorithm in by_algorithm
        ]

    def get_active_for_user(
        self,
        user_id: UUID,
        algorithm: str | None = None,
    ) -> UserCryptoKey:
        selected = algorithm or self.default_algorithm
        self._provider(selected)
        key = self.keys.get_active(user_id, selected)
        if key is None or key.key_purpose != PURPOSE_BY_ALGORITHM[selected].value:
            raise CryptoKeyNotFoundError
        return key

    def get_public_key(
        self,
        user_id: UUID,
        algorithm: str | None = None,
    ) -> UserCryptoKey:
        return self.get_active_for_user(user_id, algorithm)

    def recover_private_key(
        self,
        user_id: UUID,
        key_id: UUID,
        *,
        expected_algorithm: str | None = None,
        expected_version: int | None = None,
        expected_purpose: KeyPurpose | None = None,
    ) -> bytes:
        key = self.keys.get_for_user(user_id, key_id)
        if key is None:
            raise PrivateKeyUnavailableError
        purpose = PURPOSE_BY_ALGORITHM.get(key.algorithm)
        if (
            purpose is None
            or key.key_purpose != purpose.value
            or (expected_algorithm is not None and key.algorithm != expected_algorithm)
            or (expected_version is not None and key.key_version != expected_version)
            or (expected_purpose is not None and purpose is not expected_purpose)
        ):
            raise PrivateKeyUnavailableError
        try:
            provider = self._provider(key.algorithm)
        except ValueError as exc:
            raise PrivateKeyUnavailableError from exc
        if (
            key.private_key_protection_algorithm
            != self.secret_protection.algorithm_id
            or key.private_key_protection_version != PRIVATE_KEY_PROTECTION_VERSION
        ):
            raise PrivateKeyUnavailableError
        context = SecretContext(
            user_id=key.user_id,
            key_id=key.id,
            algorithm=key.algorithm,
            key_version=key.key_version,
        )
        try:
            private_key = self.secret_protection.unprotect(
                key.encrypted_private_key,
                key.private_key_nonce,
                context,
            )
            if len(private_key) != provider.private_key_size:
                raise PrivateKeyUnavailableError
            return private_key
        except SecretProtectionError as exc:
            raise PrivateKeyUnavailableError from exc
