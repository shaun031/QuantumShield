"""Version-1 canonical signed package schemas shared by sign and verify paths."""

import base64
import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

from app.models.crypto_metadata import CryptoMetadata
from app.models.file import File
from app.models.file_share import FileShare
from app.models.share_crypto_metadata import ShareCryptoMetadata


PAYLOAD_VERSION = 1


def canonical_bytes(value: dict) -> bytes:
    """UTF-8 JSON with sorted keys and no insignificant whitespace."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _id(value: UUID | None) -> str | None:
    return str(value) if value is not None else None


def _binary(value: bytes | None) -> str | None:
    return base64.b64encode(value).decode("ascii") if value is not None else None


def _time(value: datetime) -> str:
    if value is None:
        raise ValueError("Missing signed creation timestamp")
    normalized = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return normalized.isoformat(timespec="microseconds").replace("+00:00", "Z")


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_key_package(metadata: CryptoMetadata) -> dict:
    """Every persisted owner-envelope field that can affect recovery."""
    return {
        "aad_version": metadata.aad_version,
        "classical_algorithm": metadata.classical_algorithm,
        "combiner_version": metadata.combiner_version,
        "content_algorithm": metadata.content_algorithm,
        "content_nonce": _binary(metadata.content_nonce),
        "crypto_suite_id": metadata.crypto_suite_id,
        "crypto_suite_version": metadata.crypto_suite_version,
        "crypto_version": metadata.crypto_version,
        "ephemeral_public_key": _binary(metadata.ephemeral_public_key),
        "kdf_algorithm": metadata.kdf_algorithm,
        "kdf_salt": _binary(metadata.kdf_salt),
        "kem_algorithm": metadata.kem_algorithm,
        "kem_ciphertext": _binary(metadata.kem_ciphertext),
        "key_wrap_algorithm": metadata.key_wrap_algorithm,
        "key_wrap_nonce": _binary(metadata.key_wrap_nonce),
        "recipient_classical_key_id": _id(metadata.recipient_classical_key_id),
        "recipient_classical_key_version": metadata.recipient_classical_key_version,
        "recipient_key_id": _id(metadata.recipient_key_id),
        "recipient_key_version": metadata.recipient_key_version,
        "security_architecture": metadata.security_architecture,
        "security_level": metadata.security_level,
        "wrapped_file_key": _binary(metadata.wrapped_file_key),
    }


def share_key_package(metadata: ShareCryptoMetadata) -> dict:
    """Every persisted recipient envelope field that can affect recovery."""
    return {
        "aad_version": metadata.aad_version,
        "classical_algorithm": metadata.classical_algorithm,
        "combiner_version": metadata.combiner_version,
        "crypto_suite_id": metadata.crypto_suite_id,
        "crypto_suite_version": metadata.crypto_suite_version,
        "crypto_version": metadata.crypto_version,
        "ephemeral_public_key": _binary(metadata.ephemeral_public_key),
        "kdf_algorithm": metadata.kdf_algorithm,
        "kdf_salt": _binary(metadata.kdf_salt),
        "kem_algorithm": metadata.kem_algorithm,
        "kem_ciphertext": _binary(metadata.kem_ciphertext),
        "key_wrap_algorithm": metadata.key_wrap_algorithm,
        "key_wrap_nonce": _binary(metadata.key_wrap_nonce),
        "recipient_classical_key_id": _id(metadata.recipient_classical_key_id),
        "recipient_classical_key_version": metadata.recipient_classical_key_version,
        "recipient_key_id": _id(metadata.recipient_key_id),
        "recipient_key_version": metadata.recipient_key_version,
        "security_architecture": metadata.security_architecture,
        "security_level": metadata.security_level,
        "wrapped_file_key": _binary(metadata.wrapped_file_key),
    }


def package_digest(package: dict) -> str:
    return digest_bytes(canonical_bytes(package))


def file_payload(file: File, *, ciphertext_sha256: str, key_package_sha256: str,
                 signer_key_id: UUID, signer_key_version: int,
                 algorithm: str, profile_id: str) -> dict:
    return {
        "signature_payload_version": PAYLOAD_VERSION,
        "scope": "FILE",
        "file_id": str(file.id),
        "owner_id": str(file.owner_id),
        "sender_id": str(file.owner_id),
        "signing_key_id": str(signer_key_id),
        "signing_key_version": signer_key_version,
        "signature_algorithm": algorithm,
        "signature_profile_id": profile_id,
        "created_at": _time(file.created_at),
        "original_filename": file.original_filename,
        "mime_type": file.mime_type,
        "file_size": file.file_size,
        "plaintext_sha256": file.sha256,
        "ciphertext_sha256": ciphertext_sha256,
        "key_package_sha256": key_package_sha256,
        "security_level": file.crypto_metadata.security_level,
        "crypto_suite_id": file.crypto_metadata.crypto_suite_id,
        "crypto_version": file.crypto_metadata.crypto_version,
        "security_architecture": file.crypto_metadata.security_architecture,
        "selection_mode": file.selection_mode,
        "sensitivity": file.sensitivity,
        "document_category": file.document_category,
        "recommended_security_level": file.recommended_security_level,
        "policy_version": file.policy_version,
        "decision_reasons": file.decision_reasons,
        "policy_rules": file.policy_rules,
        "user_override": file.user_override,
    }


def share_payload(share: FileShare, *, ciphertext_sha256: str,
                  key_package_sha256: str, file_package_sha256: str,
                  signer_key_id: UUID, signer_key_version: int,
                  algorithm: str, profile_id: str) -> dict:
    return {
        "signature_payload_version": PAYLOAD_VERSION,
        "scope": "SHARE",
        "share_id": str(share.id),
        "file_id": str(share.file_id),
        "owner_id": str(share.file.owner_id),
        "sender_id": str(share.sender_id),
        "recipient_id": str(share.recipient_id),
        "signing_key_id": str(signer_key_id),
        "signing_key_version": signer_key_version,
        "signature_algorithm": algorithm,
        "signature_profile_id": profile_id,
        "created_at": _time(share.created_at),
        "permission": share.permission,
        # Version 1 authenticates the immutable creation snapshot. Phase 12
        # lifecycle status is mutable and is enforced separately; historical
        # signatures were all created while status was ACTIVE.
        "status": "ACTIVE",
        "ciphertext_sha256": ciphertext_sha256,
        "key_package_sha256": key_package_sha256,
        "file_package_sha256": file_package_sha256,
        "security_level": share.crypto_access.security_level,
        "crypto_suite_id": share.crypto_access.crypto_suite_id,
        "crypto_version": share.crypto_access.crypto_version,
        "security_architecture": share.crypto_access.security_architecture,
    }
