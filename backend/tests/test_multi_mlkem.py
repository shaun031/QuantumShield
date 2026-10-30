"""Phase 7 multi-ML-KEM selection, compatibility, and no-downgrade tests."""

from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.crypto.aes import AESService
from app.crypto.kdf import HKDFService
from app.crypto.kem.factory import build_kem_registry
from app.crypto.kem.registry import UnsupportedKEMAlgorithmError
from app.crypto.kem_key_protection import (
    KEMFileContext,
    KEMKeyProtectionError,
    MLKEMFileKeyProtector,
)
from app.crypto.security_levels import SecurityLevelPolicy
from app.models.file import File
from app.models.file_share import FileShare
from app.models.share_crypto_metadata import ShareCryptoMetadata
from app.models.user_crypto_key import UserCryptoKey
from app.storage.local import LocalStorageService
from tests.test_files import register_and_login


LEVELS = (
    ("LOW", "ML-KEM-512", 800, 1632, 768),
    ("STANDARD", "ML-KEM-768", 1184, 64, 1088),
    ("HIGH", "ML-KEM-1024", 1568, 64, 1568),
)


def upload_at_level(
    client: TestClient,
    headers: dict[str, str],
    level: str,
    content: bytes,
):
    return client.post(
        "/api/files/upload",
        headers=headers,
        data={"security_level": level},
        files={"file": (f"{level.lower()}.txt", content, "text/plain")},
    )


@pytest.mark.parametrize(
    ("level", "algorithm", "public_size", "private_size", "ciphertext_size"),
    LEVELS,
)
def test_registry_round_trip_for_every_parameter_set(
    level: str,
    algorithm: str,
    public_size: int,
    private_size: int,
    ciphertext_size: int,
) -> None:
    registry = build_kem_registry()
    provider = registry.get(algorithm)
    keypair = provider.generate_keypair()
    encapsulated = provider.encapsulate(keypair.public_key)

    assert SecurityLevelPolicy().get_algorithm(level) == algorithm
    assert len(keypair.public_key) == public_size
    assert len(keypair.private_key) == private_size
    assert len(encapsulated.ciphertext) == ciphertext_size
    assert provider.decapsulate(
        keypair.private_key, encapsulated.ciphertext
    ) == encapsulated.shared_secret


def test_registry_rejects_unknown_algorithm_without_fallback() -> None:
    with pytest.raises(UnsupportedKEMAlgorithmError, match="Unsupported KEM algorithm"):
        build_kem_registry().get("ML-KEM-999")


@pytest.mark.parametrize("source_algorithm", [item[1] for item in LEVELS])
def test_cross_algorithm_key_or_ciphertext_use_fails(source_algorithm: str) -> None:
    registry = build_kem_registry()
    source = registry.get(source_algorithm)
    keypair = source.generate_keypair()
    encapsulated = source.encapsulate(keypair.public_key)
    wrong_algorithm = next(
        algorithm for _, algorithm, *_ in LEVELS if algorithm != source_algorithm
    )
    wrong = registry.get(wrong_algorithm)

    with pytest.raises(ValueError):
        wrong.encapsulate(keypair.public_key)
    with pytest.raises(ValueError):
        wrong.decapsulate(keypair.private_key, encapsulated.ciphertext)


@pytest.mark.parametrize(("level", "algorithm", "_pk", "_sk", "_ct"), LEVELS)
def test_upload_and_owner_download_use_exact_stored_algorithm(
    client: TestClient,
    db_session: Session,
    level: str,
    algorithm: str,
    _pk: int,
    _sk: int,
    _ct: int,
) -> None:
    _, headers = register_and_login(client, f"owner-{level.lower()}@example.com")
    content = f"Phase 7 {level} owner round trip".encode()

    response = upload_at_level(client, headers, level, content)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["security_level"] == level
    assert body["kem_algorithm"] == algorithm
    record = db_session.get(File, UUID(body["id"]))
    assert record is not None and record.crypto_metadata is not None
    assert record.crypto_metadata.security_level == level
    assert record.crypto_metadata.kem_algorithm == algorithm
    key = db_session.get(UserCryptoKey, record.crypto_metadata.recipient_key_id)
    assert key is not None and key.algorithm == algorithm
    downloaded = client.get(f"/api/files/{body['id']}/download", headers=headers)
    assert downloaded.status_code == 200 and downloaded.content == content


def test_upload_defaults_to_standard_and_rejects_unknown_level(client: TestClient) -> None:
    _, headers = register_and_login(client, "default-level@example.com")
    default = client.post(
        "/api/files/upload",
        headers=headers,
        files={"file": ("default.txt", b"default", "text/plain")},
    )
    unknown = upload_at_level(client, headers, "ADAPTIVE", b"invalid")
    mis_cased = upload_at_level(client, headers, "high", b"invalid")

    assert default.status_code == 201
    assert default.json()["security_level"] == "STANDARD"
    assert default.json()["kem_algorithm"] == "ML-KEM-768"
    assert unknown.status_code == mis_cased.status_code == 422


@pytest.mark.parametrize(("level", "algorithm", "_pk", "_sk", "_ct"), LEVELS)
def test_sharing_uses_file_algorithm_and_one_ciphertext(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
    level: str,
    algorithm: str,
    _pk: int,
    _sk: int,
    _ct: int,
) -> None:
    alice, alice_headers = register_and_login(
        client, f"alice-{level.lower()}@example.com"
    )
    bob, bob_headers = register_and_login(client, f"bob-{level.lower()}@example.com")
    content = f"shared at {level}".encode()
    uploaded = upload_at_level(client, alice_headers, level, content).json()
    before = {path: path.read_bytes() for path in storage_service.root.rglob("*.enc")}

    shared = client.post(
        f"/api/files/{uploaded['id']}/share",
        headers=alice_headers,
        json={"recipient_id": bob["id"]},
    )

    assert shared.status_code == 201, shared.text
    assert shared.json()["security_level"] == level
    assert shared.json()["kem_algorithm"] == algorithm
    assert {path: path.read_bytes() for path in storage_service.root.rglob("*.enc")} == before
    access = db_session.scalar(
        select(ShareCryptoMetadata).where(
            ShareCryptoMetadata.file_share_id == UUID(shared.json()["id"])
        )
    )
    assert access is not None
    assert access.security_level == level and access.kem_algorithm == algorithm
    recipient_key = db_session.get(UserCryptoKey, access.recipient_key_id)
    assert recipient_key is not None and recipient_key.algorithm == algorithm
    download = client.get(
        f"/api/shares/{shared.json()['id']}/download", headers=bob_headers
    )
    assert download.status_code == 200 and download.content == content
    assert shared.json()["sender"]["id"] == alice["id"]


def test_missing_high_key_rejects_without_downgrade_or_partial_share(
    client: TestClient,
    db_session: Session,
) -> None:
    _, alice_headers = register_and_login(client, "alice-high-missing@example.com")
    bob, _ = register_and_login(client, "bob-high-missing@example.com")
    uploaded = upload_at_level(client, alice_headers, "HIGH", b"high content").json()
    high_key = db_session.scalar(
        select(UserCryptoKey).where(
            UserCryptoKey.user_id == UUID(bob["id"]),
            UserCryptoKey.algorithm == "ML-KEM-1024",
        )
    )
    assert high_key is not None
    high_key.is_active = False
    db_session.commit()

    response = client.post(
        f"/api/files/{uploaded['id']}/share",
        headers=alice_headers,
        json={"recipient_id": bob["id"]},
    )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Recipient does not have an active ML-KEM-1024 key"
    }
    assert db_session.scalar(select(func.count()).select_from(FileShare)) == 0
    assert db_session.scalar(select(func.count()).select_from(ShareCryptoMetadata)) == 0


@pytest.mark.parametrize("algorithm", [item[1] for item in LEVELS])
def test_wrong_private_key_and_algorithm_context_fail_file_key_wrap(
    algorithm: str,
) -> None:
    registry = build_kem_registry()
    provider = registry.get(algorithm)
    intended = provider.generate_keypair()
    wrong = provider.generate_keypair()
    protector = MLKEMFileKeyProtector(registry, HKDFService(), AESService())
    context = KEMFileContext(
        file_id=uuid4(),
        owner_id=uuid4(),
        recipient_key_id=uuid4(),
        recipient_key_version=1,
        kem_algorithm=algorithm,
        plaintext_size=12,
    )
    protected = protector.protect(b"K" * 32, intended.public_key, context)
    common = {
        "kem_ciphertext": protected.kem_ciphertext,
        "kdf_salt": protected.kdf_salt,
        "wrapped_file_key": protected.wrapped_file_key,
        "key_wrap_nonce": protected.key_wrap_nonce,
        "kdf_algorithm": protected.kdf_algorithm,
        "key_wrap_algorithm": protected.key_wrap_algorithm,
    }

    assert protector.recover(
        recipient_private_key=intended.private_key,
        context=context,
        **common,
    ) == b"K" * 32

    with pytest.raises(KEMKeyProtectionError):
        protector.recover(
            recipient_private_key=wrong.private_key,
            context=context,
            **common,
        )
    tampered_kem = bytearray(protected.kem_ciphertext)
    tampered_kem[0] ^= 1
    with pytest.raises(KEMKeyProtectionError):
        protector.recover(
            recipient_private_key=intended.private_key,
            context=context,
            **{**common, "kem_ciphertext": bytes(tampered_kem)},
        )
    tampered_wrap = bytearray(protected.wrapped_file_key)
    tampered_wrap[-1] ^= 1
    with pytest.raises(KEMKeyProtectionError):
        protector.recover(
            recipient_private_key=intended.private_key,
            context=context,
            **{**common, "wrapped_file_key": bytes(tampered_wrap)},
        )
    wrong_algorithm = next(item[1] for item in LEVELS if item[1] != algorithm)
    with pytest.raises(KEMKeyProtectionError):
        protector.recover(
            recipient_private_key=intended.private_key,
            context=KEMFileContext(
                **{**context.__dict__, "kem_algorithm": wrong_algorithm}
            ),
            **common,
        )


def test_algorithm_metadata_and_exact_public_key_api(client: TestClient) -> None:
    user, headers = register_and_login(client, "algorithm-api@example.com")
    algorithms = client.get("/api/crypto/algorithms", headers=headers)

    assert algorithms.status_code == 200
    assert [(item["security_level"], item["algorithm"]) for item in algorithms.json()] == [
        ("LOW", "ML-KEM-512"),
        ("STANDARD", "ML-KEM-768"),
        ("HIGH", "ML-KEM-1024"),
    ]
    assert [item["is_default"] for item in algorithms.json()] == [False, True, False]
    for _, algorithm, public_size, *_ in LEVELS:
        response = client.get(
            f"/api/crypto/public-key/{user['id']}?algorithm={algorithm}",
            headers=headers,
        )
        assert response.status_code == 200
        assert response.json()["algorithm"] == algorithm
        import base64

        assert len(base64.b64decode(response.json()["public_key_base64"])) == public_size
    unsupported = client.get(
        f"/api/crypto/public-key/{user['id']}?algorithm=ML-KEM-999",
        headers=headers,
    )
    assert unsupported.status_code == 422


@pytest.mark.parametrize(("level", "_algorithm", "_pk", "_sk", "_ct"), LEVELS)
def test_tampered_physical_ciphertext_fails_for_every_level(
    client: TestClient,
    db_session: Session,
    storage_service: LocalStorageService,
    level: str,
    _algorithm: str,
    _pk: int,
    _sk: int,
    _ct: int,
) -> None:
    _, headers = register_and_login(client, f"tamper-{level.lower()}@example.com")
    plaintext = f"authenticated {level} content".encode()
    uploaded = upload_at_level(client, headers, level, plaintext).json()
    record = db_session.get(File, UUID(uploaded["id"]))
    assert record is not None
    object_path = storage_service.resolve_path(record.storage_path)
    ciphertext = bytearray(object_path.read_bytes())
    ciphertext[-1] ^= 1
    object_path.write_bytes(ciphertext)

    response = client.get(f"/api/files/{uploaded['id']}/download", headers=headers)

    assert response.status_code == 422
    assert plaintext not in response.content
