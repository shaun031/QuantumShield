"""Phase 9 provider, suite, version, and end-to-end agility tests."""

import hashlib
from dataclasses import replace
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_crypto_key_service,
    get_crypto_suite_registry,
    get_encryption_service,
)
from app.crypto.aes import AESService
from app.crypto.encryption import CryptoContext
from app.crypto.key_wrap import AESGCMKeyWrapProvider
from app.crypto.kdf import HKDFService
from app.crypto.kem.factory import build_kem_registry
from app.crypto.kem_key_protection import PQ_AAD_VERSION, PQ_CRYPTO_VERSION
from app.crypto.provider_registry import ProviderRegistry, UnsupportedProviderError
from app.crypto.suites import (
    CryptoSuiteMismatchError,
    CryptoSuiteNotActiveError,
    CryptoSuiteRegistry,
    CryptoSuiteStatus,
    UnsupportedCryptoSuiteError,
)
from app.crypto.security_levels import SecurityLevel, SecurityLevelPolicy
from app.crypto.share_key_protection import MLKEMShareKeyProtector, ShareKeyContext
from app.crypto.suite_key_protection import (
    SUITE_AAD_VERSION,
    SUITE_CRYPTO_VERSION,
    SuiteFileKeyContext,
    SuiteFileKeyProtector,
    SuiteKeyProtectionError,
)
from cryptography.exceptions import InvalidTag
from app.models.crypto_metadata import CryptoMetadata
from app.models.file import File
from app.models.file_share import FileShare
from app.models.share_crypto_metadata import ShareCryptoMetadata
from app.models.user_crypto_key import UserCryptoKey
from app.services.files import FileIntegrityError, FileService
from app.services.security_policy import SecurityPolicyEngine
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login
from tests.test_sharing import create_share


SUITES = (
    ("LOW", "QS-PQ-512-V1", "ML-KEM-512"),
    ("STANDARD", "QS-PQ-768-V1", "ML-KEM-768"),
    ("HIGH", "QS-PQ-1024-V1", "ML-KEM-1024"),
)


def test_provider_and_suite_registries_are_strict() -> None:
    aes = AESService()
    registry = ProviderRegistry("AEAD", (aes,))
    assert registry.get("AES-256-GCM") is aes
    registry.assert_all_available()
    with pytest.raises(UnsupportedProviderError):
        registry.get("AES-128-GCM")
    with pytest.raises(ValueError):
        ProviderRegistry("AEAD", (aes, aes))

    suites = get_crypto_suite_registry()
    standard = suites.get_suite("QS-PQ-768-V1")
    assert standard.content_algorithm == "AES-256-GCM"
    assert standard.kdf_algorithm == "HKDF-SHA256"
    assert standard.key_wrap_algorithm == "KEK-AES-256-GCM"
    with pytest.raises(UnsupportedCryptoSuiteError):
        suites.get_suite("UNTRUSTED-SUITE")
    with pytest.raises(CryptoSuiteMismatchError):
        suites.validate_metadata(
            suite_id=standard.suite_id,
            suite_version=standard.version,
            security_level=standard.security_level,
            content_algorithm=standard.content_algorithm,
            kem_algorithm="ML-KEM-512",
            kdf_algorithm=standard.kdf_algorithm,
            key_wrap_algorithm=standard.key_wrap_algorithm,
        )


def test_aead_and_key_wrap_provider_contracts_fail_closed() -> None:
    aead = AESService()
    key = aead.generate_key()
    nonce = aead.generate_nonce()
    assert len(key) == aead.key_size == 32
    assert len(nonce) == aead.nonce_size == 12
    encrypted = aead.encrypt(b"provider contract", key, b"context", nonce)
    assert aead.decrypt(encrypted.ciphertext, key, nonce, b"context") == b"provider contract"
    with pytest.raises(InvalidTag):
        aead.decrypt(encrypted.ciphertext, key, nonce, b"wrong-context")

    wrapper = AESGCMKeyWrapProvider(aead)
    wrapped = wrapper.wrap_key(b"F" * 32, b"W" * 32, b"wrap-context")
    assert wrapper.unwrap_key(
        wrapped.ciphertext, b"W" * 32, wrapped.nonce, b"wrap-context"
    ) == b"F" * 32
    with pytest.raises(InvalidTag):
        wrapper.unwrap_key(
            wrapped.ciphertext, b"X" * 32, wrapped.nonce, b"wrap-context"
        )
    with pytest.raises(InvalidTag):
        wrapper.unwrap_key(
            wrapped.ciphertext, b"W" * 32, wrapped.nonce, b"wrong-context"
        )


def test_suite_rejects_recipient_key_from_wrong_kem() -> None:
    suites = get_crypto_suite_registry()
    standard = suites.get_suite("QS-PQ-768-V1")
    wrong = suites.get_suite("QS-PQ-1024-V1").kem.generate_keypair()
    correct = standard.kem.generate_keypair()
    context = SuiteFileKeyContext(
        file_id=uuid4(),
        owner_id=uuid4(),
        recipient_key_id=uuid4(),
        recipient_key_version=1,
        crypto_suite_id=standard.suite_id,
        crypto_suite_version=standard.version,
        security_level=SecurityLevel.STANDARD,
        plaintext_size=5,
    )
    protector = SuiteFileKeyProtector(suites)
    protected = protector.protect(b"F" * 32, correct.public_key, context)
    with pytest.raises(SuiteKeyProtectionError):
        protector.recover(
            recipient_private_key=wrong.private_key,
            kem_ciphertext=protected.kem_ciphertext,
            kdf_salt=protected.kdf_salt,
            wrapped_file_key=protected.wrapped_file_key,
            key_wrap_nonce=protected.key_wrap_nonce,
            kem_algorithm=protected.kem_algorithm,
            kdf_algorithm=protected.kdf_algorithm,
            key_wrap_algorithm=protected.key_wrap_algorithm,
            content_algorithm=standard.content_algorithm,
            context=context,
        )


def test_direct_suite_encryption_orchestration_round_trip() -> None:
    service = get_encryption_service()
    suite = get_crypto_suite_registry().get_suite("QS-PQ-768-V1")
    recipient = suite.kem.generate_keypair()
    recipient_key_id = uuid4()
    plaintext = b"direct suite orchestration"
    context = CryptoContext(
        file_id=uuid4(),
        owner_id=uuid4(),
        plaintext_size=len(plaintext),
        crypto_version=SUITE_CRYPTO_VERSION,
        aad_version=SUITE_AAD_VERSION,
    )
    encrypted = service.encrypt_file_for_suite(
        plaintext, context,
        recipient_key_id=recipient_key_id,
        recipient_key_version=1,
        recipient_public_key=recipient.public_key,
        crypto_suite_id=suite.suite_id,
        security_level=suite.security_level,
    )
    recovered = service.decrypt_file_v3(
        encrypted.ciphertext,
        recipient_private_key=recipient.private_key,
        content_nonce=encrypted.content_nonce,
        wrapped_file_key=encrypted.wrapped_file_key,
        key_wrap_nonce=encrypted.key_wrap_nonce,
        content_algorithm=encrypted.content_algorithm,
        key_wrap_algorithm=encrypted.key_wrap_algorithm,
        kem_algorithm=encrypted.kem_algorithm,
        kem_ciphertext=encrypted.kem_ciphertext,
        kdf_algorithm=encrypted.kdf_algorithm,
        kdf_salt=encrypted.kdf_salt,
        recipient_key_id=recipient_key_id,
        recipient_key_version=1,
        crypto_suite_id=suite.suite_id,
        crypto_suite_version=suite.version,
        security_level=suite.security_level,
        crypto_version=encrypted.crypto_version,
        aad_version=encrypted.aad_version,
        context=context,
    )
    assert recovered == plaintext


def test_suite_lifecycle_rules_separate_new_encryption_from_decryption() -> None:
    active = get_crypto_suite_registry().get_suite("QS-PQ-768-V1")
    deprecated = replace(active, status=CryptoSuiteStatus.DEPRECATED)
    registry = CryptoSuiteRegistry((deprecated,))
    assert registry.get_suite(active.suite_id) is deprecated
    with pytest.raises(CryptoSuiteNotActiveError):
        registry.get_suite(active.suite_id, for_encryption=True)
    level_policy = SecurityLevelPolicy(suite_registry=registry)
    assert level_policy.get_supported_levels() == ()
    with pytest.raises(UnsupportedCryptoSuiteError):
        level_policy.get_suite_id(SecurityLevel.STANDARD)

    disabled = replace(active, status=CryptoSuiteStatus.DISABLED)
    registry = CryptoSuiteRegistry((disabled,))
    with pytest.raises(UnsupportedCryptoSuiteError):
        registry.get_suite(active.suite_id)


def test_suite_discovery_is_authenticated_and_safe(client: TestClient) -> None:
    assert client.get("/api/crypto/suites").status_code == 401
    _, headers = register_and_login(client, "suite-list@example.com")
    response = client.get("/api/crypto/suites", headers=headers)

    assert response.status_code == 200
    assert [item["suite_id"] for item in response.json()] == [item[1] for item in SUITES] + [
        "QS-HYBRID-512-V1", "QS-HYBRID-768-V1", "QS-HYBRID-1024-V1"
    ]
    for item in response.json():
        assert item["available"] is True
        assert item["status"] == "ACTIVE"
        assert set(item) == {
            "suite_id", "version", "security_level", "status", "content_aead",
            "kem", "kdf", "key_wrap", "description", "available", "architecture", "classical_algorithm",
        }


def test_every_suite_uploads_shares_and_downloads_one_ciphertext(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    owner, owner_headers = register_and_login(client, "suite-owner@example.com")
    recipient, recipient_headers = register_and_login(client, "suite-recipient@example.com")

    for level, suite_id, kem in SUITES:
        plaintext = f"suite round trip {suite_id}".encode()
        upload = client.post(
            "/api/files/upload",
            headers=owner_headers,
            data={"selection_mode": "MANUAL", "security_level": level},
            files={"file": (f"{level}.txt", plaintext, "text/plain")},
        )
        assert upload.status_code == 201
        uploaded = upload.json()
        assert uploaded["crypto_suite_id"] == suite_id
        assert uploaded["kem_algorithm"] == kem
        assert uploaded["crypto_version"] == 3

        record = db_session.get(File, UUID(uploaded["id"]))
        assert record is not None
        object_path = storage_service.resolve_path(record.storage_path)
        before = object_path.read_bytes()
        shared = create_share(
            client, owner_headers, uploaded["id"], recipient["id"]
        )
        assert shared.status_code == 201
        assert shared.json()["crypto_suite_id"] == suite_id
        assert object_path.read_bytes() == before
        access = db_session.scalar(
            select(ShareCryptoMetadata).where(
                ShareCryptoMetadata.file_share_id == UUID(shared.json()["id"])
            )
        )
        assert access is not None
        assert access.crypto_version == 2
        assert access.crypto_suite_id == suite_id
        assert client.get(
            f"/api/files/{uploaded['id']}/download", headers=owner_headers
        ).content == plaintext
        assert client.get(
            f"/api/shares/{shared.json()['id']}/download", headers=recipient_headers
        ).content == plaintext

    assert owner["id"] != recipient["id"]


def test_stored_file_suite_confusion_fails_before_key_lookup(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    _, headers = register_and_login(client, "confusion@example.com")
    uploaded = client.post(
        "/api/files/upload",
        headers=headers,
        files={"file": ("confusion.txt", b"must remain secret", "text/plain")},
    ).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None and record.crypto_metadata is not None
    service = FileService(
        db_session, storage_service, get_encryption_service(),
        None, 1024 * 1024, SecurityPolicyEngine(),
    )

    record.crypto_metadata.kem_algorithm = "ML-KEM-512"
    with pytest.raises(FileIntegrityError):
        service.recover_file_key_for_owner(record)
    record.crypto_metadata.kem_algorithm = "ML-KEM-768"
    record.crypto_metadata.crypto_suite_id = "UNREGISTERED-SUITE"
    with pytest.raises(FileIntegrityError):
        service.recover_file_key_for_owner(record)
    db_session.rollback()


def test_historical_share_envelope_remains_downloadable(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
) -> None:
    owner, owner_headers = register_and_login(client, "legacy-share-owner@example.com")
    recipient, recipient_headers = register_and_login(
        client, "legacy-share-recipient@example.com"
    )
    plaintext = b"legacy share content"
    uploaded = client.post(
        "/api/files/upload",
        headers=owner_headers,
        files={"file": ("legacy-share.txt", plaintext, "text/plain")},
    ).json()
    shared = create_share(client, owner_headers, uploaded["id"], recipient["id"])
    assert shared.status_code == 201
    access = db_session.scalar(
        select(ShareCryptoMetadata).where(
            ShareCryptoMetadata.file_share_id == UUID(shared.json()["id"])
        )
    )
    record = db_session.get(File, UUID(uploaded["id"]))
    recipient_key = db_session.scalar(
        select(UserCryptoKey).where(
            UserCryptoKey.user_id == UUID(recipient["id"]),
            UserCryptoKey.algorithm == "ML-KEM-768",
        )
    )
    assert access is not None and record is not None and recipient_key is not None
    file_service = FileService(
        db_session, storage_service, get_encryption_service(),
        get_crypto_key_service(db_session), 1024 * 1024, SecurityPolicyEngine(),
    )
    file_key = file_service.recover_file_key_for_owner(record)
    legacy = MLKEMShareKeyProtector(
        build_kem_registry(), HKDFService(), AESService()
    )
    protected = legacy.protect(
        file_key,
        recipient_key.public_key,
        ShareKeyContext(
            share_id=UUID(shared.json()["id"]),
            file_id=record.id,
            owner_id=UUID(owner["id"]),
            recipient_id=UUID(recipient["id"]),
            recipient_key_id=recipient_key.id,
            recipient_key_version=recipient_key.key_version,
            kem_algorithm=recipient_key.algorithm,
            plaintext_size=record.file_size,
        ),
    )
    access.kem_ciphertext = protected.kem_ciphertext
    access.kdf_salt = protected.kdf_salt
    access.wrapped_file_key = protected.wrapped_file_key
    access.key_wrap_nonce = protected.key_wrap_nonce
    access.crypto_version = 1
    access.aad_version = 1
    historical_share = db_session.get(FileShare, UUID(shared.json()["id"]))
    historical_share.signature = None
    historical_share.signature_required = False
    db_session.commit()

    response = client.get(
        f"/api/shares/{shared.json()['id']}/download", headers=recipient_headers
    )
    assert response.status_code == 200
    assert response.content == plaintext


@pytest.mark.parametrize("with_phase8_policy", [False, True])
def test_historical_version_two_file_remains_downloadable(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
    with_phase8_policy: bool,
) -> None:
    label = "phase8" if with_phase8_policy else "phase5"
    owner, headers = register_and_login(client, f"historical-{label}@example.com")
    owner_id = UUID(owner["id"])
    recipient_key = db_session.scalar(
        select(UserCryptoKey).where(
            UserCryptoKey.user_id == owner_id,
            UserCryptoKey.algorithm == "ML-KEM-768",
        )
    )
    assert recipient_key is not None
    plaintext = b"historical phase-five ciphertext"
    file_id = uuid4()
    context = CryptoContext(
        file_id=file_id,
        owner_id=owner_id,
        plaintext_size=len(plaintext),
        crypto_version=PQ_CRYPTO_VERSION,
        aad_version=PQ_AAD_VERSION,
    )
    encrypted = get_encryption_service().encrypt_file_for_recipient(
        plaintext,
        context,
        recipient_key_id=recipient_key.id,
        recipient_key_version=recipient_key.key_version,
        recipient_public_key=recipient_key.public_key,
        kem_algorithm=recipient_key.algorithm,
    )
    object_key = f"{owner_id}/{uuid4().hex}.enc"
    storage_service.save_bytes(encrypted.ciphertext, object_key)
    file_record = File(
            id=file_id,
            owner_id=owner_id,
            original_filename="historical-v2.txt",
            stored_filename=object_key.rsplit("/", 1)[-1],
            storage_path=object_key,
            file_size=len(plaintext),
            mime_type="text/plain",
            sha256=hashlib.sha256(plaintext).hexdigest(),
            crypto_metadata=CryptoMetadata(
                content_algorithm=encrypted.content_algorithm,
                content_nonce=encrypted.content_nonce,
                wrapped_file_key=encrypted.wrapped_file_key,
                key_wrap_algorithm=encrypted.key_wrap_algorithm,
                key_wrap_nonce=encrypted.key_wrap_nonce,
                kem_algorithm=encrypted.kem_algorithm,
                kem_ciphertext=encrypted.kem_ciphertext,
                kdf_algorithm=encrypted.kdf_algorithm,
                kdf_salt=encrypted.kdf_salt,
                recipient_key_id=encrypted.recipient_key_id,
                recipient_key_version=encrypted.recipient_key_version,
                security_level="STANDARD",
                crypto_suite_id="QS-PQ-768-V1",
                crypto_suite_version=1,
                crypto_version=encrypted.crypto_version,
                aad_version=encrypted.aad_version,
            ),
        )
    if with_phase8_policy:
        file_record.selection_mode = "AUTO"
        file_record.sensitivity = "INTERNAL"
        file_record.document_category = "GENERAL"
        file_record.recommended_security_level = "STANDARD"
        file_record.policy_version = "adaptive-v1"
        file_record.decision_reasons = ["Historical Phase 8 decision."]
        file_record.policy_rules = [
            {
                "rule": "historical_test",
                "required_level": "STANDARD",
                "message": "Historical Phase 8 decision.",
            }
        ]
        file_record.user_override = False
    db_session.add(file_record)
    db_session.commit()

    response = client.get(f"/api/files/{file_id}/download", headers=headers)
    assert response.status_code == 200
    assert response.content == plaintext
    if with_phase8_policy:
        decision = client.get(
            f"/api/files/{file_id}/security-decision", headers=headers
        )
        assert decision.status_code == 200
        assert decision.json()["crypto_suite_id"] == "QS-PQ-768-V1"
