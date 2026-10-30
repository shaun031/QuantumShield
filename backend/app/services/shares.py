"""Secure recipient-specific sharing without duplicating encrypted objects."""

import hashlib
import hmac
import logging
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from app.crypto.share_key_protection import (
    MLKEMShareKeyProtector,
    SHARE_CRYPTO_VERSION,
    ShareKeyContext,
    ShareKeyProtectionError,
)
from app.crypto.security_levels import SecurityLevelPolicy
from app.crypto.security_levels import SecurityLevel
from app.crypto.suite_key_protection import (
    SUITE_SHARE_AAD_VERSION,
    SUITE_SHARE_CRYPTO_VERSION,
    SuiteKeyProtectionError,
    SuiteShareKeyContext,
    SuiteShareKeyProtector,
)
from app.crypto.suites import CryptoSuiteRegistry
from app.crypto.suites import SecurityArchitecture
from app.crypto.identifiers import X25519
from app.crypto.hybrid_key_protection import (
    HybridContext, HybridKeyProtector, HYBRID_SHARE_VERSION,
    HYBRID_SHARE_AAD_VERSION, HYBRID_COMBINER_VERSION,
)
from app.models.file_share import FileShare
from app.models.share_crypto_metadata import ShareCryptoMetadata
from app.models.user import User
from app.repositories.share import ShareRepository
from app.repositories.audit import AuditRepository
from app.repositories.user import UserRepository
from app.services.crypto_keys import (
    CryptoKeyNotFoundError,
    CryptoKeyService,
    PrivateKeyUnavailableError,
)
from app.services.files import FileIntegrityError, FileService
from app.services.signatures import SignatureIntegrityError, VerificationResult, VerificationStatus
from app.storage.local import InvalidStorageKeyError


logger = logging.getLogger(__name__)


class SelfShareError(ValueError):
    """Raised when an owner tries to share a file with themselves."""


class RecipientNotFoundError(LookupError):
    """Raised when a requested recipient is absent or inactive."""


class RecipientCryptoKeyRequiredError(ValueError):
    """Raised when the recipient has no usable ML-KEM key."""

    def __init__(self, algorithm: str) -> None:
        self.algorithm = algorithm
        super().__init__(algorithm)


class DuplicateShareError(ValueError):
    """Raised when an active file/recipient share already exists."""


class ShareNotAccessibleError(LookupError):
    """Raised for an absent share or one outside the caller's role."""


class ShareIntegrityError(ValueError):
    """Raised when a recipient envelope or shared ciphertext is invalid."""


class ShareRevokedError(PermissionError):
    """A historical share no longer grants future application access."""


class ShareService:
    def __init__(
        self,
        session: Session,
        files: FileService,
        crypto_keys: CryptoKeyService,
        protector: MLKEMShareKeyProtector,
        suite_registry: CryptoSuiteRegistry,
        suite_protector: SuiteShareKeyProtector,
        hybrid_protector: HybridKeyProtector | None = None,
    ) -> None:
        self.session = session
        self.file_service = files
        self.crypto_keys = crypto_keys
        self.protector = protector
        self.suite_registry = suite_registry
        self.suite_protector = suite_protector
        self.hybrid_protector = hybrid_protector
        self.shares = ShareRepository(session)
        self.audit = AuditRepository(session)
        self.users = UserRepository(session)

    def create_share(self, sender: User, file_id: UUID, recipient_id: UUID) -> FileShare:
        if sender.id == recipient_id:
            raise SelfShareError
        file_record = self.file_service.get_file(sender, file_id)
        recipient = self.users.get_by_id(recipient_id)
        if recipient is None or not recipient.is_active:
            raise RecipientNotFoundError
        if self.shares.get_duplicate(file_id, recipient_id) is not None:
            raise DuplicateShareError
        file_metadata = file_record.crypto_metadata
        try:
            ciphertext = self.file_service.storage.read_bytes(file_record.storage_path)
        except FileNotFoundError as exc:
            raise FileIntegrityError from exc
        except InvalidStorageKeyError as exc:
            raise FileIntegrityError from exc
        if self.file_service.signatures is not None:
            self.file_service.signatures.require_valid(file_record, ciphertext)
        elif file_record.signature_required:
            raise SignatureIntegrityError
        if (
            file_metadata is None
            or file_metadata.kem_algorithm is None
            or file_metadata.kdf_algorithm is None
            or file_metadata.crypto_suite_id is None
            or file_metadata.crypto_suite_version is None
            or file_metadata.security_level is None
        ):
            raise FileIntegrityError
        try:
            suite = self.suite_registry.validate_metadata(
                suite_id=file_metadata.crypto_suite_id,
                suite_version=file_metadata.crypto_suite_version,
                security_level=file_metadata.security_level,
                content_algorithm=file_metadata.content_algorithm,
                kem_algorithm=file_metadata.kem_algorithm,
                kdf_algorithm=file_metadata.kdf_algorithm,
                key_wrap_algorithm=file_metadata.key_wrap_algorithm,
                architecture=file_metadata.security_architecture,
                classical_algorithm=file_metadata.classical_algorithm,
            )
            self.suite_registry.get_suite(suite.suite_id, for_encryption=True)
        except ValueError as exc:
            raise FileIntegrityError from exc
        try:
            recipient_key = self.crypto_keys.get_active_for_user(
                recipient_id,
                suite.kem_algorithm,
            )
        except CryptoKeyNotFoundError as exc:
            raise RecipientCryptoKeyRequiredError(suite.kem_algorithm) from exc
        classical_key = None
        if suite.architecture is SecurityArchitecture.HYBRID:
            try:
                classical_key = self.crypto_keys.get_active_for_user(recipient_id, X25519)
            except CryptoKeyNotFoundError as exc:
                raise RecipientCryptoKeyRequiredError(X25519) from exc

        share_id = uuid4()
        file_key = b""
        try:
            file_key = self.file_service.recover_file_key_for_owner(file_record)
            context = SuiteShareKeyContext(
                share_id=share_id,
                file_id=file_record.id,
                owner_id=file_record.owner_id,
                recipient_id=recipient.id,
                recipient_key_id=recipient_key.id,
                recipient_key_version=recipient_key.key_version,
                crypto_suite_id=suite.suite_id,
                crypto_suite_version=suite.version,
                security_level=suite.security_level,
                plaintext_size=file_record.file_size,
            )
            try:
                if classical_key is None:
                    protected = self.suite_protector.protect(file_key, recipient_key.public_key, context)
                else:
                    if self.hybrid_protector is None:
                        raise ValueError("Hybrid provider unavailable")
                    hybrid_context = HybridContext(
                        purpose="SHARE", file_id=file_record.id, owner_id=file_record.owner_id,
                        recipient_id=recipient.id, recipient_kem_key_id=recipient_key.id,
                        recipient_kem_key_version=recipient_key.key_version,
                        recipient_classical_key_id=classical_key.id,
                        recipient_classical_key_version=classical_key.key_version,
                        suite_id=suite.suite_id, suite_version=suite.version,
                        security_level=suite.security_level.value,
                        plaintext_size=file_record.file_size,
                        crypto_version=HYBRID_SHARE_VERSION, aad_version=HYBRID_SHARE_AAD_VERSION,
                        share_id=share_id,
                    )
                    protected = self.hybrid_protector.protect(
                        file_key, recipient_key.public_key, classical_key.public_key, hybrid_context)
            except ValueError as exc:
                raise FileIntegrityError from exc
            share = FileShare(
                id=share_id,
                file_id=file_record.id,
                sender_id=sender.id,
                recipient_id=recipient.id,
                file=file_record,
                sender=sender,
                recipient=recipient,
                permission="READ",
                status="ACTIVE",
                signature_required=self.file_service.signatures is not None,
                created_at=datetime.now(UTC),
                crypto_access=ShareCryptoMetadata(
                    recipient_key_id=recipient_key.id,
                    recipient_key_version=recipient_key.key_version,
                    security_level=suite.security_level.value,
                    crypto_suite_id=suite.suite_id,
                    crypto_suite_version=suite.version,
                    kem_algorithm=suite.kem_algorithm,
                    kem_ciphertext=protected.kem_ciphertext,
                    kdf_algorithm=suite.kdf_algorithm,
                    kdf_salt=protected.kdf_salt,
                    key_wrap_algorithm=suite.key_wrap_algorithm,
                    wrapped_file_key=protected.wrapped_file_key,
                    key_wrap_nonce=protected.key_wrap_nonce,
                    crypto_version=HYBRID_SHARE_VERSION if classical_key else SUITE_SHARE_CRYPTO_VERSION,
                    aad_version=HYBRID_SHARE_AAD_VERSION if classical_key else SUITE_SHARE_AAD_VERSION,
                    security_architecture=suite.architecture.value,
                    classical_algorithm=suite.classical_algorithm,
                    ephemeral_public_key=protected.ephemeral_public_key if classical_key else None,
                    recipient_classical_key_id=classical_key.id if classical_key else None,
                    recipient_classical_key_version=classical_key.key_version if classical_key else None,
                    combiner_version=HYBRID_COMBINER_VERSION if classical_key else None,
                ),
            )
            self.shares.add(share)
            self.session.flush()
            if self.file_service.signatures is not None:
                self.file_service.signatures.sign_share(share, ciphertext)
            self.audit.record("SHARE_CREATED", actor_user_id=sender.id,
                              file_id=file_record.id, share_id=share.id,
                              recipient_id=recipient.id, new_status="ACTIVE")
            self.session.commit()
            self.session.refresh(share)
        except IntegrityError as exc:
            self.session.rollback()
            raise DuplicateShareError from exc
        except Exception:
            self.session.rollback()
            raise
        finally:
            file_key = b""

        logger.info(
            "File share %s created for file %s from user %s to user %s with suite %s v%s.",
            share.id,
            file_record.id,
            sender.id,
            recipient.id,
            share.crypto_access.crypto_suite_id,
            share.crypto_access.crypto_suite_version,
        )
        return share

    def list_received(self, recipient: User, *, limit: int, offset: int) -> list[FileShare]:
        return self.shares.list_received(recipient.id, limit=limit, offset=offset)

    def list_sent(self, sender: User, *, limit: int, offset: int) -> list[FileShare]:
        return self.shares.list_sent(sender.id, limit=limit, offset=offset)

    def get_share(self, user: User, share_id: UUID) -> FileShare:
        share = self.shares.get_visible(user.id, share_id)
        if share is None:
            raise ShareNotAccessibleError
        return share

    def revoke_share(self, sender: User, share_id: UUID,
                     reason: str | None = None) -> FileShare:
        """Atomically revoke one recipient grant while retaining its history."""
        share = self.shares.get_for_sender(sender.id, share_id)
        if share is None or share.file.owner_id != sender.id:
            raise ShareNotAccessibleError
        if share.status == "REVOKED":
            if share.crypto_access is not None and share.crypto_access.is_active:
                try:
                    share.crypto_access.is_active = False
                    self.session.commit()
                    self.session.refresh(share)
                except Exception:
                    self.session.rollback()
                    raise
            return share
        if (share.status != "ACTIVE" or share.crypto_access is None
            or self.audit.was_revoked(share.id)):
            raise ShareIntegrityError
        normalized_reason = reason.strip() if reason is not None else None
        if normalized_reason == "":
            normalized_reason = None
        if normalized_reason is not None and len(normalized_reason) > 255:
            raise ValueError("Revocation reason is too long")
        revoked_at = datetime.now(UTC)
        try:
            changed = self.session.execute(
                update(FileShare).where(
                    FileShare.id == share.id,
                    FileShare.sender_id == sender.id,
                    FileShare.status == "ACTIVE",
                ).values(status="REVOKED", revoked_at=revoked_at,
                         revoked_by_user_id=sender.id, revoke_reason=normalized_reason)
            ).rowcount
            if changed != 1:
                self.session.rollback()
                current = self.shares.get_for_sender(sender.id, share_id)
                if current is not None and current.status == "REVOKED":
                    return current
                raise ShareIntegrityError
            package_changed = self.session.execute(
                update(ShareCryptoMetadata).where(
                    ShareCryptoMetadata.file_share_id == share.id,
                ).values(is_active=False)
            ).rowcount
            if package_changed != 1:
                raise ShareIntegrityError
            self.audit.record("SHARE_REVOKED", actor_user_id=sender.id,
                              file_id=share.file_id, share_id=share.id,
                              recipient_id=share.recipient_id,
                              previous_status="ACTIVE", new_status="REVOKED",
                              reason=normalized_reason)
            self.session.commit()
            self.session.refresh(share)
            self.session.refresh(share.crypto_access)
        except Exception:
            self.session.rollback()
            raise
        logger.info("Share %s revoked by owner %s for recipient %s.",
                    share.id, sender.id, share.recipient_id)
        return share

    def _deny_revoked_download(self, recipient: User, share: FileShare) -> None:
        try:
            self.audit.record("SHARE_DOWNLOAD_DENIED_REVOKED",
                              actor_user_id=recipient.id, file_id=share.file_id,
                              share_id=share.id, recipient_id=share.recipient_id,
                              previous_status=share.status, new_status=share.status)
            self.session.commit()
        except SQLAlchemyError:
            self.session.rollback()
            logger.warning("Could not persist denied-download audit for share %s.", share.id)
        raise ShareRevokedError

    def get_download(self, recipient: User, share_id: UUID) -> tuple[FileShare, bytes]:
        share = self.shares.get_for_recipient(recipient.id, share_id)
        if share is None:
            raise ShareNotAccessibleError
        if share.status != "ACTIVE" or self.audit.was_revoked(share.id):
            self._deny_revoked_download(recipient, share)
        access = share.crypto_access
        if access is None or not access.is_active or access.file_share_id != share.id \
                or share.file.crypto_metadata is None:
            raise ShareIntegrityError
        try:
            ciphertext = self.file_service.storage.read_bytes(share.file.storage_path)
        except FileNotFoundError as exc:
            raise ShareIntegrityError from exc
        except InvalidStorageKeyError as exc:
            raise ShareIntegrityError from exc
        if self.file_service.signatures is not None:
            self.file_service.signatures.require_valid(share.file, ciphertext)
            self.file_service.signatures.require_valid(share.file, ciphertext, share)
        elif share.file.signature_required or share.signature_required:
            raise SignatureIntegrityError
        if (
            access.crypto_suite_id != share.file.crypto_metadata.crypto_suite_id
            or access.crypto_suite_version != share.file.crypto_metadata.crypto_suite_version
            or access.security_level != share.file.crypto_metadata.security_level
            or access.security_architecture != share.file.crypto_metadata.security_architecture
        ):
            raise ShareIntegrityError
        private_key = b""
        classical_private = b""
        file_key = b""
        try:
            private_key = self.crypto_keys.recover_private_key(
                recipient.id,
                access.recipient_key_id,
                expected_algorithm=access.kem_algorithm,
                expected_version=access.recipient_key_version,
            )
            if access.crypto_version == SHARE_CRYPTO_VERSION:
                SecurityLevelPolicy().validate_pair(
                    access.security_level,
                    access.kem_algorithm,
                )
                context = ShareKeyContext(
                    share_id=share.id,
                    file_id=share.file.id,
                    owner_id=share.file.owner_id,
                    recipient_id=share.recipient_id,
                    recipient_key_id=access.recipient_key_id,
                    recipient_key_version=access.recipient_key_version,
                    kem_algorithm=access.kem_algorithm,
                    plaintext_size=share.file.file_size,
                    crypto_version=access.crypto_version,
                    aad_version=access.aad_version,
                )
                file_key = self.protector.recover(
                    recipient_private_key=private_key,
                    kem_ciphertext=access.kem_ciphertext,
                    kdf_salt=access.kdf_salt,
                    wrapped_file_key=access.wrapped_file_key,
                    key_wrap_nonce=access.key_wrap_nonce,
                    kdf_algorithm=access.kdf_algorithm,
                    key_wrap_algorithm=access.key_wrap_algorithm,
                    context=context,
                )
            elif (
                access.crypto_version == SUITE_SHARE_CRYPTO_VERSION
                and access.aad_version == SUITE_SHARE_AAD_VERSION
            ):
                context = SuiteShareKeyContext(
                    share_id=share.id,
                    file_id=share.file.id,
                    owner_id=share.file.owner_id,
                    recipient_id=share.recipient_id,
                    recipient_key_id=access.recipient_key_id,
                    recipient_key_version=access.recipient_key_version,
                    crypto_suite_id=access.crypto_suite_id,
                    crypto_suite_version=access.crypto_suite_version,
                    security_level=SecurityLevel(access.security_level),
                    plaintext_size=share.file.file_size,
                    crypto_version=access.crypto_version,
                    aad_version=access.aad_version,
                )
                file_key = self.suite_protector.recover(
                    recipient_private_key=private_key,
                    kem_ciphertext=access.kem_ciphertext,
                    kdf_salt=access.kdf_salt,
                    wrapped_file_key=access.wrapped_file_key,
                    key_wrap_nonce=access.key_wrap_nonce,
                    kem_algorithm=access.kem_algorithm,
                    kdf_algorithm=access.kdf_algorithm,
                    key_wrap_algorithm=access.key_wrap_algorithm,
                    content_algorithm=share.file.crypto_metadata.content_algorithm,
                    context=context,
                )
            elif access.crypto_version == HYBRID_SHARE_VERSION and access.aad_version == HYBRID_SHARE_AAD_VERSION:
                if (self.hybrid_protector is None or access.security_architecture != SecurityArchitecture.HYBRID.value
                    or access.classical_algorithm != X25519 or access.combiner_version != HYBRID_COMBINER_VERSION
                    or access.ephemeral_public_key is None or access.recipient_classical_key_id is None
                    or access.recipient_classical_key_version is None):
                    raise ShareIntegrityError
                suite = self.suite_registry.validate_metadata(
                    suite_id=access.crypto_suite_id, suite_version=access.crypto_suite_version,
                    security_level=access.security_level,
                    content_algorithm=share.file.crypto_metadata.content_algorithm,
                    kem_algorithm=access.kem_algorithm, kdf_algorithm=access.kdf_algorithm,
                    key_wrap_algorithm=access.key_wrap_algorithm,
                    architecture=access.security_architecture, classical_algorithm=access.classical_algorithm)
                classical_record = self.crypto_keys.keys.get_for_user(
                    recipient.id, access.recipient_classical_key_id)
                if (classical_record is None or classical_record.algorithm != X25519
                    or classical_record.key_version != access.recipient_classical_key_version):
                    raise ShareIntegrityError
                classical_private = self.crypto_keys.recover_private_key(
                    recipient.id, classical_record.id, expected_algorithm=X25519,
                    expected_version=classical_record.key_version)
                context = HybridContext(
                    purpose="SHARE", file_id=share.file.id, owner_id=share.file.owner_id,
                    recipient_id=recipient.id, recipient_kem_key_id=access.recipient_key_id,
                    recipient_kem_key_version=access.recipient_key_version,
                    recipient_classical_key_id=classical_record.id,
                    recipient_classical_key_version=classical_record.key_version,
                    suite_id=suite.suite_id, suite_version=suite.version,
                    security_level=suite.security_level.value, plaintext_size=share.file.file_size,
                    crypto_version=access.crypto_version, aad_version=access.aad_version,
                    share_id=share.id)
                file_key = self.hybrid_protector.recover(
                    kem_private_key=private_key, classical_private_key=classical_private,
                    classical_public_key=classical_record.public_key,
                    ephemeral_public_key=access.ephemeral_public_key,
                    kem_ciphertext=access.kem_ciphertext, kdf_salt=access.kdf_salt,
                    wrapped_file_key=access.wrapped_file_key,
                    key_wrap_nonce=access.key_wrap_nonce, context=context)
            else:
                raise ShareIntegrityError
            plaintext = self.file_service.decrypt_with_file_key(share.file, file_key, ciphertext=ciphertext)
        except (
            PrivateKeyUnavailableError,
            ShareKeyProtectionError,
            SuiteKeyProtectionError,
            FileIntegrityError,
            ValueError,
        ) as exc:
            logger.warning(
                "Shared-file decryption failed for share %s (%s).",
                share.id,
                type(exc).__name__,
            )
            raise ShareIntegrityError from exc
        finally:
            private_key = b""
            classical_private = b""
            file_key = b""

        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual_hash, share.file.sha256):
            raise ShareIntegrityError
        logger.info(
            "Shared file %s downloaded by recipient %s through share %s using suite %s v%s.",
            share.file_id,
            recipient.id,
            share.id,
            access.crypto_suite_id,
            access.crypto_suite_version,
        )
        return share, plaintext

    def verify_share(self, user: User, share_id: UUID) -> VerificationResult:
        share = self.get_share(user, share_id)
        try:
            ciphertext = self.file_service.storage.read_bytes(share.file.storage_path)
        except FileNotFoundError as exc:
            raise ShareIntegrityError from exc
        except InvalidStorageKeyError as exc:
            raise ShareIntegrityError from exc
        if self.file_service.signatures is None:
            raise SignatureIntegrityError
        file_result = self.file_service.signatures.verify(share.file, ciphertext)
        share_result = self.file_service.signatures.verify(share.file, ciphertext, share)
        if file_result.status is VerificationStatus.INVALID:
            return VerificationResult(VerificationStatus.INVALID, "SHARE")
        return share_result
