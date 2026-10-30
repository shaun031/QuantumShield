"""Sign and independently verify versioned encrypted FILE/SHARE packages."""

import hmac
import logging
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.crypto.key_purpose import KeyPurpose
from app.crypto.signature_payload import (
    PAYLOAD_VERSION, canonical_bytes, digest_bytes, file_key_package,
    file_payload, package_digest, share_key_package, share_payload,
)
from app.crypto.signature_profiles import SignatureProfileRegistry
from app.models.digital_signature import DigitalSignature
from app.models.file import File
from app.models.file_share import FileShare
from app.models.user_crypto_key import UserCryptoKey
from app.services.crypto_keys import CryptoKeyNotFoundError, CryptoKeyService, PrivateKeyUnavailableError


logger = logging.getLogger(__name__)


class SignatureIntegrityError(ValueError):
    """A required signature, its binding, or signed content is invalid."""


class SigningKeyRequiredError(ValueError):
    """The sender's configured signing key cannot be used."""


class VerificationStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    LEGACY_UNSIGNED = "LEGACY_UNSIGNED"


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    scope: str
    algorithm: str | None = None
    profile_id: str | None = None
    signer_user_id: str | None = None


class SignatureService:
    def __init__(self, session: Session, keys: CryptoKeyService,
                 profiles: SignatureProfileRegistry, default_algorithm: str) -> None:
        self.session = session
        self.keys = keys
        self.profiles = profiles
        self.default_algorithm = default_algorithm

    def _signing_key(self, user_id):
        try:
            return self.keys.get_active_for_user(user_id, self.default_algorithm)
        except CryptoKeyNotFoundError as exc:
            raise SigningKeyRequiredError from exc

    def _sign(self, *, file: File, share: FileShare | None, ciphertext: bytes) -> DigitalSignature:
        key = self._signing_key(file.owner_id)
        profile = self.profiles.for_algorithm(key.algorithm, for_signing=True)
        if key.key_purpose != KeyPurpose.SIGNATURE.value:
            raise SignatureIntegrityError
        ciphertext_hash = digest_bytes(ciphertext)
        file_package_hash = package_digest(file_key_package(file.crypto_metadata))
        if share is None:
            scope = "FILE"
            package_hash = file_package_hash
            payload = file_payload(file, ciphertext_sha256=ciphertext_hash,
                                   key_package_sha256=package_hash,
                                   signer_key_id=key.id, signer_key_version=key.key_version,
                                   algorithm=key.algorithm, profile_id=profile.profile_id)
        else:
            scope = "SHARE"
            package_hash = package_digest(share_key_package(share.crypto_access))
            payload = share_payload(share, ciphertext_sha256=ciphertext_hash,
                                    key_package_sha256=package_hash,
                                    file_package_sha256=file_package_hash,
                                    signer_key_id=key.id, signer_key_version=key.key_version,
                                    algorithm=key.algorithm, profile_id=profile.profile_id)
        try:
            private = self.keys.recover_private_key(file.owner_id, key.id,
                                                    expected_algorithm=key.algorithm,
                                                    expected_version=key.key_version,
                                                    expected_purpose=KeyPurpose.SIGNATURE)
        except PrivateKeyUnavailableError as exc:
            raise SigningKeyRequiredError from exc
        signature = profile.provider.sign(private, canonical_bytes(payload))
        record = DigitalSignature(file=file, share=share, signer_user_id=file.owner_id,
                                  signing_key_id=key.id, signing_key_version=key.key_version,
                                  algorithm=key.algorithm, profile_id=profile.profile_id,
                                  payload_version=PAYLOAD_VERSION, scope=scope,
                                  signature=signature, ciphertext_sha256=ciphertext_hash,
                                  key_package_sha256=package_hash)
        self.session.add(record)
        return record

    def sign_file(self, file: File, ciphertext: bytes) -> DigitalSignature:
        return self._sign(file=file, share=None, ciphertext=ciphertext)

    def sign_share(self, share: FileShare, ciphertext: bytes) -> DigitalSignature:
        if share.status != "ACTIVE":
            raise SignatureIntegrityError
        return self._sign(file=share.file, share=share, ciphertext=ciphertext)

    def _record(self, file: File, share: FileShare | None) -> DigitalSignature | None:
        statement = select(DigitalSignature).where(DigitalSignature.file_id == file.id)
        statement = statement.where(DigitalSignature.file_share_id.is_(None) if share is None
                                    else DigitalSignature.file_share_id == share.id)
        return self.session.scalar(statement)

    def verify(self, file: File, ciphertext: bytes,
               share: FileShare | None = None) -> VerificationResult:
        scope = "SHARE" if share is not None else "FILE"
        record = self._record(file, share)
        required = share.signature_required if share is not None else file.signature_required
        if record is None:
            return VerificationResult(VerificationStatus.INVALID if required else VerificationStatus.LEGACY_UNSIGNED, scope)
        invalid = VerificationResult(VerificationStatus.INVALID, scope)
        try:
            if (record.scope != scope or record.payload_version != PAYLOAD_VERSION
                or record.signer_user_id != file.owner_id
                or (share is not None and share.sender_id != file.owner_id)):
                return invalid
            profile = self.profiles.get(record.profile_id)
            key = self.session.get(UserCryptoKey, record.signing_key_id)
            if (profile.algorithm != record.algorithm or profile.payload_version != record.payload_version
                or key is None or key.user_id != record.signer_user_id
                or key.key_purpose != KeyPurpose.SIGNATURE.value
                or key.algorithm != record.algorithm or key.key_version != record.signing_key_version):
                return invalid
            ciphertext_hash = digest_bytes(ciphertext)
            file_package_hash = package_digest(file_key_package(file.crypto_metadata))
            if share is None:
                package_hash = file_package_hash
                payload = file_payload(file, ciphertext_sha256=ciphertext_hash,
                                       key_package_sha256=package_hash,
                                       signer_key_id=key.id, signer_key_version=key.key_version,
                                       algorithm=key.algorithm, profile_id=profile.profile_id)
            else:
                package_hash = package_digest(share_key_package(share.crypto_access))
                payload = share_payload(share, ciphertext_sha256=ciphertext_hash,
                                        key_package_sha256=package_hash,
                                        file_package_sha256=file_package_hash,
                                        signer_key_id=key.id, signer_key_version=key.key_version,
                                        algorithm=key.algorithm, profile_id=profile.profile_id)
            if (not hmac.compare_digest(ciphertext_hash, record.ciphertext_sha256)
                or not hmac.compare_digest(package_hash, record.key_package_sha256)
                or not profile.provider.verify(key.public_key, canonical_bytes(payload), record.signature)):
                return invalid
            return VerificationResult(VerificationStatus.VALID, scope, record.algorithm,
                                      record.profile_id, str(record.signer_user_id))
        except (AttributeError, KeyError, TypeError, ValueError):
            return invalid

    def require_valid(self, file: File, ciphertext: bytes,
                      share: FileShare | None = None) -> VerificationResult:
        result = self.verify(file, ciphertext, share)
        if result.status is VerificationStatus.INVALID:
            logger.warning("Signature verification rejected %s package for file %s (share %s).",
                           result.scope, file.id, share.id if share else None)
            raise SignatureIntegrityError
        return result
