"""Owner-scoped encrypted file lifecycle and consistency rules."""

from __future__ import annotations

import hashlib
import hmac
import logging
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from fastapi import UploadFile
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.crypto.encryption import (
    CryptoContext,
    CryptoIntegrityError,
    EncryptionService,
    UnsupportedCryptoMetadataError,
)
from app.crypto.kem_key_protection import PQ_CRYPTO_VERSION
from app.crypto.security_levels import SecurityLevel
from app.crypto.suite_key_protection import SUITE_AAD_VERSION, SUITE_CRYPTO_VERSION
from app.crypto.hybrid_key_protection import HYBRID_FILE_VERSION, HYBRID_FILE_AAD_VERSION, HYBRID_COMBINER_VERSION
from app.crypto.identifiers import X25519
from app.crypto.suites import SecurityArchitecture
from app.crypto.versioning import FILE_CRYPTO_VERSION_HANDLERS
from app.models.crypto_metadata import CryptoMetadata
from app.models.file import File
from app.models.user import User
from app.repositories.file import FileRepository
from app.repositories.audit import AuditRepository
from app.storage.local import InvalidStorageKeyError, LocalStorageService
from app.services.crypto_keys import (
    CryptoKeyNotFoundError,
    CryptoKeyService,
    PrivateKeyUnavailableError,
)
from app.services.security_policy import (
    DocumentCategory,
    SecurityAssessmentInput,
    SecurityPolicyEngine,
    SelectionMode,
    Sensitivity,
)
from app.services.signatures import SignatureIntegrityError, VerificationResult

if TYPE_CHECKING:
    from app.services.signatures import SignatureService


logger = logging.getLogger(__name__)
UPLOAD_CHUNK_SIZE = 1024 * 1024
_UNSAFE_DISPLAY_CHARACTERS = re.compile(r'[<>:"/\\|?*\x00-\x1f\x7f]')


class InvalidUploadError(ValueError):
    """Raised when required upload metadata is absent or unusable."""


class UploadTooLargeError(ValueError):
    """Raised after an upload exceeds the configured in-memory limit."""


class FileNotAccessibleError(LookupError):
    """Raised for missing, unowned, or physically unavailable files."""


class LegacyFileRequiresMigrationError(ValueError):
    """Raised when a Phase 3 plaintext record has no crypto metadata."""


class FileIntegrityError(ValueError):
    """Raised when authenticated decryption or correctness validation fails."""


class CryptoSetupRequiredError(ValueError):
    """Raised when an existing user has not provisioned an ML-KEM key."""


def sanitize_original_filename(filename: str | None) -> str:
    """Return safe display metadata, never a filesystem path."""

    if filename is None:
        raise InvalidUploadError("A filename is required")
    basename = filename.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    sanitized = _UNSAFE_DISPLAY_CHARACTERS.sub("_", basename).strip(" .")
    if not sanitized:
        raise InvalidUploadError("A valid filename is required")
    return sanitized[:255]


def generate_stored_filename() -> str:
    return f"{uuid4().hex}.enc"


def normalize_mime_type(content_type: str | None) -> str:
    if not content_type:
        return "application/octet-stream"
    normalized = "".join(
        character for character in content_type if 32 <= ord(character) < 127
    ).strip()
    return normalized[:255] or "application/octet-stream"


async def read_bounded_upload(
    upload: UploadFile,
    max_size_bytes: int,
) -> tuple[bytes, str]:
    """Read a bounded upload into memory without writing plaintext to disk."""

    plaintext = bytearray()
    digest = hashlib.sha256()
    try:
        while chunk := await upload.read(UPLOAD_CHUNK_SIZE):
            if len(plaintext) + len(chunk) > max_size_bytes:
                plaintext.clear()
                raise UploadTooLargeError
            plaintext.extend(chunk)
            digest.update(chunk)
        return bytes(plaintext), digest.hexdigest()
    finally:
        await upload.close()


class FileService:
    def __init__(
        self,
        session: Session,
        storage: LocalStorageService,
        encryption: EncryptionService,
        crypto_keys: CryptoKeyService,
        max_upload_size_bytes: int,
        security_policy: SecurityPolicyEngine,
        signatures: "SignatureService | None" = None,
    ) -> None:
        self.session = session
        self.storage = storage
        self.encryption = encryption
        self.crypto_keys = crypto_keys
        self.max_upload_size_bytes = max_upload_size_bytes
        self.security_policy = security_policy
        self.signatures = signatures
        self.files = FileRepository(session)
        self.audit = AuditRepository(session)

    async def upload_file(
        self,
        owner: User,
        upload: UploadFile,
        security_level: SecurityLevel | None = SecurityLevel.STANDARD,
        *,
        selection_mode: SelectionMode = SelectionMode.MANUAL,
        sensitivity: Sensitivity | None = None,
        document_category: DocumentCategory | None = None,
        security_architecture: SecurityArchitecture = SecurityArchitecture.PQ_ONLY,
    ) -> File:
        original_filename = sanitize_original_filename(upload.filename)
        mime_type = normalize_mime_type(upload.content_type)
        plaintext, plaintext_sha256 = await read_bounded_upload(
            upload,
            self.max_upload_size_bytes,
        )
        plaintext_size = len(plaintext)
        decision = self.security_policy.evaluate(
            SecurityAssessmentInput(
                file_name=original_filename,
                file_size=plaintext_size,
                mime_type=mime_type,
                sensitivity=sensitivity,
                document_category=document_category,
            ),
            selection_mode,
            security_level,
            security_architecture,
        )
        selected_level = decision.selected_level
        suite = self.encryption.get_suite_for_new_encryption(decision.crypto_suite_id)
        kem_algorithm = suite.kem_algorithm
        try:
            recipient_key = self.crypto_keys.get_active_for_user(
                owner.id,
                kem_algorithm,
            )
        except CryptoKeyNotFoundError as exc:
            plaintext = b""
            raise CryptoSetupRequiredError from exc
        classical_key = None
        if suite.architecture is SecurityArchitecture.HYBRID:
            try:
                classical_key = self.crypto_keys.get_active_for_user(owner.id, X25519)
            except CryptoKeyNotFoundError as exc:
                plaintext = b""
                raise CryptoSetupRequiredError from exc

        file_id = uuid4()
        stored_filename = generate_stored_filename()
        object_key = f"{owner.id}/{stored_filename}"
        context = CryptoContext(
            file_id=file_id,
            owner_id=owner.id,
            plaintext_size=plaintext_size,
            crypto_version=HYBRID_FILE_VERSION if classical_key else SUITE_CRYPTO_VERSION,
            aad_version=HYBRID_FILE_AAD_VERSION if classical_key else SUITE_AAD_VERSION,
        )
        try:
            common = dict(recipient_key_id=recipient_key.id,
                          recipient_key_version=recipient_key.key_version,
                          recipient_public_key=recipient_key.public_key,
                          crypto_suite_id=suite.suite_id, security_level=selected_level)
            if classical_key is None:
                encrypted = self.encryption.encrypt_file_for_suite(plaintext, context, **common)
            else:
                encrypted = self.encryption.encrypt_file_for_hybrid_suite(
                    plaintext, context, **common,
                    recipient_classical_key_id=classical_key.id,
                    recipient_classical_key_version=classical_key.key_version,
                    recipient_classical_public_key=classical_key.public_key)
        finally:
            # Release the application reference promptly; Python cannot guarantee
            # zeroization of this immutable bytes object or framework copies.
            plaintext = b""
        file_record = File(
            id=file_id,
            owner_id=owner.id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            storage_path=object_key,
            file_size=plaintext_size,
            mime_type=mime_type,
            sha256=plaintext_sha256,
            signature_required=self.signatures is not None,
            created_at=datetime.now(UTC),
            selection_mode=decision.selection_mode.value,
            sensitivity=sensitivity.value if sensitivity is not None else None,
            document_category=(
                document_category.value if document_category is not None else None
            ),
            recommended_security_level=decision.recommended_level.value,
            policy_version=decision.policy_version,
            decision_reasons=list(decision.reasons),
            policy_rules=decision.stored_rules(),
            user_override=decision.user_override,
            crypto_metadata=CryptoMetadata(
                content_algorithm=encrypted.content_algorithm,
                content_nonce=encrypted.content_nonce,
                wrapped_file_key=encrypted.wrapped_file_key,
                key_wrap_algorithm=encrypted.key_wrap_algorithm,
                key_wrap_nonce=encrypted.key_wrap_nonce,
                crypto_version=encrypted.crypto_version,
                aad_version=encrypted.aad_version,
                kem_algorithm=encrypted.kem_algorithm,
                kem_ciphertext=encrypted.kem_ciphertext,
                kdf_algorithm=encrypted.kdf_algorithm,
                kdf_salt=encrypted.kdf_salt,
                recipient_key_id=encrypted.recipient_key_id,
                recipient_key_version=encrypted.recipient_key_version,
                security_level=selected_level.value,
                crypto_suite_id=encrypted.crypto_suite_id,
                crypto_suite_version=encrypted.crypto_suite_version,
                security_architecture=encrypted.security_architecture,
                classical_algorithm=encrypted.classical_algorithm,
                ephemeral_public_key=encrypted.ephemeral_public_key,
                recipient_classical_key_id=encrypted.recipient_classical_key_id,
                recipient_classical_key_version=encrypted.recipient_classical_key_version,
                combiner_version=encrypted.combiner_version,
            ),
        )
        try:
            self.storage.save_bytes(encrypted.ciphertext, object_key)
            self.files.add(file_record)
            self.session.flush()
            if self.signatures is not None:
                self.signatures.sign_file(file_record, encrypted.ciphertext)
            self.session.commit()
            self.session.refresh(file_record)
        except Exception:
            self.session.rollback()
            try:
                self.storage.delete_file(object_key)
            except OSError as cleanup_error:
                logger.error(
                    "Encrypted upload database failure left an object needing cleanup (%s).",
                    type(cleanup_error).__name__,
                )
            raise

        logger.info(
            "Encrypted file %s uploaded for user %s in %s mode at %s using %s under %s.",
            file_record.id,
            owner.id,
            decision.selection_mode.value,
            selected_level.value,
            decision.crypto_suite_id,
            decision.policy_version,
        )
        return file_record

    def list_files(
        self,
        owner: User,
        *,
        limit: int,
        offset: int,
    ) -> list[File]:
        return self.files.list_for_owner(owner.id, limit=limit, offset=offset)

    def get_file(self, owner: User, file_id: UUID) -> File:
        file_record = self.files.get_for_owner(owner.id, file_id)
        if file_record is None:
            raise FileNotAccessibleError
        return file_record

    def recover_file_key_for_owner(self, file_record: File) -> bytes:
        """Recover only the file key from the owner's versioned envelope."""

        metadata = file_record.crypto_metadata
        if metadata is None:
            raise LegacyFileRequiresMigrationError
        context = CryptoContext(
            file_id=file_record.id,
            owner_id=file_record.owner_id,
            plaintext_size=file_record.file_size,
            crypto_version=metadata.crypto_version,
            aad_version=metadata.aad_version,
        )
        private_key = b""
        classical_private = b""
        try:
            handler = FILE_CRYPTO_VERSION_HANDLERS.get(
                metadata.crypto_version, metadata.aad_version
            )
            if handler.crypto_version == 1:
                return self.encryption.recover_file_key(
                    wrapped_file_key=metadata.wrapped_file_key,
                    key_wrap_nonce=metadata.key_wrap_nonce,
                    content_algorithm=metadata.content_algorithm,
                    key_wrap_algorithm=metadata.key_wrap_algorithm,
                    crypto_version=metadata.crypto_version,
                    aad_version=metadata.aad_version,
                    context=context,
                )
            if handler.crypto_version in {PQ_CRYPTO_VERSION, SUITE_CRYPTO_VERSION, HYBRID_FILE_VERSION}:
                if (
                    metadata.kem_algorithm is None
                    or metadata.kem_ciphertext is None
                    or metadata.kdf_algorithm is None
                    or metadata.kdf_salt is None
                    or metadata.recipient_key_id is None
                    or metadata.recipient_key_version is None
                    or metadata.security_level is None
                    or metadata.crypto_suite_id is None
                    or metadata.crypto_suite_version is None
                ):
                    raise UnsupportedCryptoMetadataError
                suite = self.encryption.suite_registry.validate_metadata(
                    suite_id=metadata.crypto_suite_id,
                    suite_version=metadata.crypto_suite_version,
                    security_level=metadata.security_level,
                    content_algorithm=metadata.content_algorithm,
                    kem_algorithm=metadata.kem_algorithm,
                    kdf_algorithm=metadata.kdf_algorithm,
                    key_wrap_algorithm=metadata.key_wrap_algorithm,
                    architecture=metadata.security_architecture,
                    classical_algorithm=metadata.classical_algorithm,
                )
                private_key = self.crypto_keys.recover_private_key(
                    file_record.owner_id,
                    metadata.recipient_key_id,
                    expected_algorithm=suite.kem_algorithm,
                    expected_version=metadata.recipient_key_version,
                )
                common = dict(
                    recipient_private_key=private_key,
                    wrapped_file_key=metadata.wrapped_file_key,
                    key_wrap_nonce=metadata.key_wrap_nonce,
                    content_algorithm=metadata.content_algorithm,
                    key_wrap_algorithm=metadata.key_wrap_algorithm,
                    kem_algorithm=metadata.kem_algorithm,
                    kem_ciphertext=metadata.kem_ciphertext,
                    kdf_algorithm=metadata.kdf_algorithm,
                    kdf_salt=metadata.kdf_salt,
                    recipient_key_id=metadata.recipient_key_id,
                    recipient_key_version=metadata.recipient_key_version,
                    crypto_version=metadata.crypto_version,
                    aad_version=metadata.aad_version,
                    context=context,
                )
                if handler.crypto_version == PQ_CRYPTO_VERSION:
                    return self.encryption.recover_file_key_v2(**common)
                if handler.crypto_version == HYBRID_FILE_VERSION:
                    if (suite.architecture is not SecurityArchitecture.HYBRID
                        or metadata.classical_algorithm != X25519
                        or metadata.combiner_version != HYBRID_COMBINER_VERSION
                        or metadata.ephemeral_public_key is None
                        or metadata.recipient_classical_key_id is None
                        or metadata.recipient_classical_key_version is None):
                        raise UnsupportedCryptoMetadataError
                    classical_record = self.crypto_keys.keys.get_for_user(
                        file_record.owner_id, metadata.recipient_classical_key_id)
                    if (classical_record is None or classical_record.algorithm != X25519
                        or classical_record.key_version != metadata.recipient_classical_key_version):
                        raise UnsupportedCryptoMetadataError
                    classical_private = self.crypto_keys.recover_private_key(
                        file_record.owner_id, classical_record.id,
                        expected_algorithm=X25519,
                        expected_version=classical_record.key_version)
                    return self.encryption.recover_file_key_v4(
                        recipient_private_key=private_key,
                        classical_private_key=classical_private,
                        classical_public_key=classical_record.public_key,
                        wrapped_file_key=metadata.wrapped_file_key,
                        key_wrap_nonce=metadata.key_wrap_nonce,
                        kem_ciphertext=metadata.kem_ciphertext,
                        kdf_salt=metadata.kdf_salt,
                        recipient_key_id=metadata.recipient_key_id,
                        recipient_key_version=metadata.recipient_key_version,
                        recipient_classical_key_id=classical_record.id,
                        recipient_classical_key_version=classical_record.key_version,
                        ephemeral_public_key=metadata.ephemeral_public_key,
                        crypto_suite_id=metadata.crypto_suite_id,
                        crypto_suite_version=metadata.crypto_suite_version,
                        security_level=SecurityLevel(metadata.security_level),
                        crypto_version=metadata.crypto_version,
                        aad_version=metadata.aad_version, context=context)
                return self.encryption.recover_file_key_v3(
                    **common,
                    crypto_suite_id=metadata.crypto_suite_id,
                    crypto_suite_version=metadata.crypto_suite_version,
                    security_level=SecurityLevel(metadata.security_level),
                )
            raise UnsupportedCryptoMetadataError
        except (
            CryptoIntegrityError,
            UnsupportedCryptoMetadataError,
            PrivateKeyUnavailableError,
            ValueError,
        ) as exc:
            raise FileIntegrityError from exc
        finally:
            private_key = b""
            classical_private = b""

    def decrypt_with_file_key(self, file_record: File, file_key: bytes,
                              *, ciphertext: bytes | None = None) -> bytes:
        """Decrypt the single stored ciphertext using an authorized file key."""

        metadata = file_record.crypto_metadata
        if metadata is None:
            raise LegacyFileRequiresMigrationError
        try:
            handler = FILE_CRYPTO_VERSION_HANDLERS.get(
                metadata.crypto_version, metadata.aad_version
            )
            if handler.crypto_version in {PQ_CRYPTO_VERSION, SUITE_CRYPTO_VERSION, HYBRID_FILE_VERSION}:
                if (
                    metadata.crypto_suite_id is None
                    or metadata.crypto_suite_version is None
                    or metadata.security_level is None
                    or metadata.kem_algorithm is None
                    or metadata.kdf_algorithm is None
                ):
                    raise UnsupportedCryptoMetadataError
                self.encryption.suite_registry.validate_metadata(
                    suite_id=metadata.crypto_suite_id,
                    suite_version=metadata.crypto_suite_version,
                    security_level=metadata.security_level,
                    content_algorithm=metadata.content_algorithm,
                    kem_algorithm=metadata.kem_algorithm,
                    kdf_algorithm=metadata.kdf_algorithm,
                    key_wrap_algorithm=metadata.key_wrap_algorithm,
                    architecture=metadata.security_architecture,
                    classical_algorithm=metadata.classical_algorithm,
                )
        except ValueError as exc:
            raise FileIntegrityError from exc
        if ciphertext is None:
            try:
                ciphertext = self.storage.read_bytes(file_record.storage_path)
            except FileNotFoundError as exc:
                raise FileNotAccessibleError from exc
            except InvalidStorageKeyError as exc:
                raise FileIntegrityError from exc
        context = CryptoContext(
            file_id=file_record.id,
            owner_id=file_record.owner_id,
            plaintext_size=file_record.file_size,
            crypto_version=metadata.crypto_version,
            aad_version=metadata.aad_version,
        )
        try:
            plaintext = self.encryption.decrypt_content(
                ciphertext,
                file_key=file_key,
                content_nonce=metadata.content_nonce,
                content_algorithm=metadata.content_algorithm,
                crypto_version=metadata.crypto_version,
                aad_version=metadata.aad_version,
                context=context,
                crypto_suite_id=metadata.crypto_suite_id,
                crypto_suite_version=metadata.crypto_suite_version,
                security_level=(
                    SecurityLevel(metadata.security_level)
                    if metadata.security_level is not None
                    else None
                ),
                kem_algorithm=metadata.kem_algorithm,
                kdf_algorithm=metadata.kdf_algorithm,
                key_wrap_algorithm=metadata.key_wrap_algorithm,
                security_architecture=metadata.security_architecture,
                classical_algorithm=metadata.classical_algorithm,
            )
        except (CryptoIntegrityError, UnsupportedCryptoMetadataError, ValueError) as exc:
            raise FileIntegrityError from exc
        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual_hash, file_record.sha256):
            raise FileIntegrityError
        return plaintext

    def get_download(self, owner: User, file_id: UUID) -> tuple[File, bytes]:
        file_record = self.get_file(owner, file_id)
        metadata = file_record.crypto_metadata
        if metadata is None:
            if file_record.signature_required:
                raise FileIntegrityError
            raise LegacyFileRequiresMigrationError

        try:
            ciphertext = self.storage.read_bytes(file_record.storage_path)
        except FileNotFoundError as exc:
            logger.warning("Encrypted object missing for file %s.", file_record.id)
            raise FileNotAccessibleError from exc
        except InvalidStorageKeyError as exc:
            logger.warning("Invalid storage key for file %s.", file_record.id)
            raise FileIntegrityError from exc
        if self.signatures is not None:
            self.signatures.require_valid(file_record, ciphertext)
        elif file_record.signature_required:
            raise SignatureIntegrityError

        file_key = b""
        try:
            file_key = self.recover_file_key_for_owner(file_record)
            plaintext = self.decrypt_with_file_key(file_record, file_key, ciphertext=ciphertext)
        except (
            CryptoIntegrityError,
            UnsupportedCryptoMetadataError,
            PrivateKeyUnavailableError,
            ValueError,
        ) as exc:
            logger.warning(
                "Authenticated decryption failed for file %s (%s).",
                file_record.id,
                type(exc).__name__,
            )
            raise FileIntegrityError from exc
        finally:
            file_key = b""

        actual_hash = hashlib.sha256(plaintext).hexdigest()
        if not hmac.compare_digest(actual_hash, file_record.sha256):
            logger.warning("Plaintext correctness hash failed for file %s.", file_record.id)
            raise FileIntegrityError
        return file_record, plaintext

    def verify_file(self, owner: User, file_id: UUID) -> VerificationResult:
        file_record = self.get_file(owner, file_id)
        try:
            ciphertext = self.storage.read_bytes(file_record.storage_path)
        except FileNotFoundError as exc:
            raise FileNotAccessibleError from exc
        except InvalidStorageKeyError as exc:
            raise FileIntegrityError from exc
        if self.signatures is None:
            raise SignatureIntegrityError
        return self.signatures.verify(file_record, ciphertext)

    def delete_file(self, owner: User, file_id: UUID) -> None:
        file_record = self.get_file(owner, file_id)
        try:
            staged = self.storage.stage_delete(file_record.storage_path)
        except InvalidStorageKeyError as exc:
            raise FileIntegrityError from exc
        if staged is None:
            logger.warning("Deleting metadata for missing physical file %s.", file_record.id)

        try:
            self.files.delete(file_record)
            self.audit.record("FILE_DELETED", actor_user_id=owner.id,
                              file_id=file_record.id)
            self.session.commit()
        except Exception:
            self.session.rollback()
            try:
                self.storage.restore_staged_delete(staged)
            except OSError as restore_error:
                logger.error(
                    "Delete rollback could not restore file %s (%s).",
                    file_id,
                    type(restore_error).__name__,
                )
            raise

        try:
            self.storage.finalize_staged_delete(staged)
        except OSError as cleanup_error:
            logger.error(
                "Staged encrypted-object cleanup failed for file %s (%s).",
                file_id,
                type(cleanup_error).__name__,
            )
        logger.info("File %s and crypto metadata deleted for user %s.", file_id, owner.id)
