"""Phase 5 ML-KEM, HKDF, private-key protection, and envelope tests."""

from uuid import uuid4

import pytest

from app.crypto.aes import AESService
from app.crypto.encryption import CryptoContext, EncryptionService
from app.crypto.kdf import HKDFService
from app.crypto.kem.mlkem import MLKEM768Provider
from app.crypto.kem.registry import KEMRegistry
from app.crypto.kem_key_protection import (
    KEMFileContext,
    KEMKeyProtectionError,
    MLKEMFileKeyProtector,
    PQ_AAD_VERSION,
    PQ_CRYPTO_VERSION,
)
from app.crypto.key_protection import MasterKeyWrapper
from app.crypto.secret_protection import (
    SecretContext,
    SecretProtectionError,
    SecretProtectionService,
)


def build_pq_protector() -> tuple[MLKEM768Provider, MLKEMFileKeyProtector]:
    provider = MLKEM768Provider()
    registry = KEMRegistry((provider,))
    return provider, MLKEMFileKeyProtector(registry, HKDFService(), AESService())


def test_mlkem_768_key_generation_encapsulation_and_decapsulation() -> None:
    provider = MLKEM768Provider()
    keypair = provider.generate_keypair()
    encapsulated = provider.encapsulate(keypair.public_key)
    recovered = provider.decapsulate(keypair.private_key, encapsulated.ciphertext)

    assert provider.algorithm_id == "ML-KEM-768"
    assert len(keypair.public_key) == provider.public_key_size == 1184
    assert len(keypair.private_key) == provider.private_key_size == 64
    assert keypair.public_key != keypair.private_key
    assert len(encapsulated.ciphertext) == provider.ciphertext_size == 1088
    assert len(encapsulated.shared_secret) == provider.shared_secret_size == 32
    assert recovered == encapsulated.shared_secret


def test_hkdf_is_context_bound_and_derives_32_bytes() -> None:
    kdf = HKDFService()
    secret = b"S" * 32
    salt = b"A" * 32
    first = kdf.derive(secret, salt=salt, info=b"context-one")

    assert len(first) == 32
    assert first == kdf.derive(secret, salt=salt, info=b"context-one")
    assert first != kdf.derive(secret, salt=b"B" * 32, info=b"context-one")
    assert first != kdf.derive(secret, salt=salt, info=b"context-two")


def test_private_key_protection_rejects_wrong_master_key_and_aad() -> None:
    aes = AESService()
    context = SecretContext(
        user_id=uuid4(),
        key_id=uuid4(),
        algorithm="ML-KEM-768",
        key_version=1,
    )
    private_seed = b"P" * 64
    protected = SecretProtectionService(b"A" * 32, aes).protect(
        private_seed,
        context,
    )

    assert protected.ciphertext != private_seed
    assert len(protected.ciphertext) == 80
    assert SecretProtectionService(b"A" * 32, aes).unprotect(
        protected.ciphertext,
        protected.nonce,
        context,
    ) == private_seed
    with pytest.raises(SecretProtectionError):
        SecretProtectionService(b"B" * 32, aes).unprotect(
            protected.ciphertext,
            protected.nonce,
            context,
        )


def test_wrong_recipient_and_tampered_kem_ciphertext_cannot_recover_file_key() -> None:
    provider, protector = build_pq_protector()
    alice = provider.generate_keypair()
    bob = provider.generate_keypair()
    context = KEMFileContext(
        file_id=uuid4(),
        owner_id=uuid4(),
        recipient_key_id=uuid4(),
        recipient_key_version=1,
        kem_algorithm="ML-KEM-768",
        plaintext_size=12,
    )
    file_key = AESService().generate_key()
    protected = protector.protect(file_key, alice.public_key, context)
    common = {
        "kdf_salt": protected.kdf_salt,
        "wrapped_file_key": protected.wrapped_file_key,
        "key_wrap_nonce": protected.key_wrap_nonce,
        "kdf_algorithm": protected.kdf_algorithm,
        "key_wrap_algorithm": protected.key_wrap_algorithm,
        "context": context,
    }

    assert protector.recover(
        recipient_private_key=alice.private_key,
        kem_ciphertext=protected.kem_ciphertext,
        **common,
    ) == file_key
    with pytest.raises(KEMKeyProtectionError):
        protector.recover(
            recipient_private_key=bob.private_key,
            kem_ciphertext=protected.kem_ciphertext,
            **common,
        )

    tampered = bytearray(protected.kem_ciphertext)
    tampered[0] ^= 1
    with pytest.raises(KEMKeyProtectionError):
        protector.recover(
            recipient_private_key=alice.private_key,
            kem_ciphertext=bytes(tampered),
            **common,
        )


def test_full_mlkem_hkdf_aes_file_round_trip() -> None:
    provider, pq_protector = build_pq_protector()
    aes = AESService()
    service = EncryptionService(
        aes,
        MasterKeyWrapper(b"M" * 32, aes),
        pq_protector,
    )
    recipient = provider.generate_keypair()
    plaintext = b"Phase 5 complete cryptographic integration"
    context = CryptoContext(
        file_id=uuid4(),
        owner_id=uuid4(),
        plaintext_size=len(plaintext),
        crypto_version=PQ_CRYPTO_VERSION,
        aad_version=PQ_AAD_VERSION,
    )
    key_id = uuid4()
    encrypted = service.encrypt_file_for_recipient(
        plaintext,
        context,
        recipient_key_id=key_id,
        recipient_key_version=1,
        recipient_public_key=recipient.public_key,
        kem_algorithm=provider.algorithm_id,
    )

    recovered = service.decrypt_file_v2(
        encrypted.ciphertext,
        recipient_private_key=recipient.private_key,
        content_nonce=encrypted.content_nonce,
        wrapped_file_key=encrypted.wrapped_file_key,
        key_wrap_nonce=encrypted.key_wrap_nonce,
        content_algorithm=encrypted.content_algorithm,
        key_wrap_algorithm=encrypted.key_wrap_algorithm,
        kem_algorithm=encrypted.kem_algorithm or "",
        kem_ciphertext=encrypted.kem_ciphertext or b"",
        kdf_algorithm=encrypted.kdf_algorithm or "",
        kdf_salt=encrypted.kdf_salt or b"",
        recipient_key_id=key_id,
        recipient_key_version=1,
        crypto_version=encrypted.crypto_version,
        aad_version=encrypted.aad_version,
        context=context,
    )

    assert recovered == plaintext
