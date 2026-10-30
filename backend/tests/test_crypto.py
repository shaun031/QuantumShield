"""Phase 4 AES-GCM and master-key wrapping unit tests."""

from uuid import uuid4

import pytest
from cryptography.exceptions import InvalidTag

from app.crypto.aes import AESService
from app.crypto.encryption import CryptoContext, CryptoIntegrityError, EncryptionService
from app.crypto.key_protection import MasterKeyWrapper


def test_aes_key_is_256_bits() -> None:
    assert len(AESService().generate_key()) == 32


def test_generated_file_keys_are_distinct() -> None:
    aes = AESService()

    assert aes.generate_key() != aes.generate_key()


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        bytes(range(256)),
        "QuantumShield — नमस्ते — encrypted".encode(),
    ],
)
def test_aes_round_trip_for_empty_binary_and_unicode(plaintext: bytes) -> None:
    aes = AESService()
    key = aes.generate_key()
    encrypted = aes.encrypt(plaintext, key, b"test-aad")

    assert aes.decrypt(
        encrypted.ciphertext,
        key,
        encrypted.nonce,
        b"test-aad",
    ) == plaintext


def test_same_plaintext_encrypted_twice_is_different() -> None:
    aes = AESService()
    key = aes.generate_key()
    first = aes.encrypt(b"same plaintext", key, b"aad")
    second = aes.encrypt(b"same plaintext", key, b"aad")

    assert first.nonce != second.nonce
    assert first.ciphertext != second.ciphertext


def test_modified_ciphertext_nonce_and_wrong_key_fail() -> None:
    aes = AESService()
    key = aes.generate_key()
    encrypted = aes.encrypt(b"authenticated", key, b"aad")
    modified_ciphertext = bytearray(encrypted.ciphertext)
    modified_ciphertext[0] ^= 1
    modified_nonce = bytearray(encrypted.nonce)
    modified_nonce[0] ^= 1

    with pytest.raises(InvalidTag):
        aes.decrypt(bytes(modified_ciphertext), key, encrypted.nonce, b"aad")
    with pytest.raises(InvalidTag):
        aes.decrypt(encrypted.ciphertext, key, bytes(modified_nonce), b"aad")
    with pytest.raises(InvalidTag):
        aes.decrypt(
            encrypted.ciphertext,
            aes.generate_key(),
            encrypted.nonce,
            b"aad",
        )


def test_file_key_wrap_round_trip_and_tamper_failures() -> None:
    aes = AESService()
    wrapper = MasterKeyWrapper(b"M" * 32, aes)
    file_key = aes.generate_key()
    wrapped = wrapper.wrap_key(file_key, b"wrap-aad")

    assert wrapped.ciphertext != file_key
    assert wrapper.unwrap_key(
        wrapped.ciphertext,
        wrapped.nonce,
        b"wrap-aad",
    ) == file_key

    modified_wrapped = bytearray(wrapped.ciphertext)
    modified_wrapped[-1] ^= 1
    modified_nonce = bytearray(wrapped.nonce)
    modified_nonce[-1] ^= 1
    with pytest.raises(InvalidTag):
        wrapper.unwrap_key(bytes(modified_wrapped), wrapped.nonce, b"wrap-aad")
    with pytest.raises(InvalidTag):
        wrapper.unwrap_key(wrapped.ciphertext, bytes(modified_nonce), b"wrap-aad")


def test_wrong_master_key_cannot_unwrap_file_key() -> None:
    aes = AESService()
    file_key = aes.generate_key()
    wrapped = MasterKeyWrapper(b"A" * 32, aes).wrap_key(file_key, b"aad")

    with pytest.raises(InvalidTag):
        MasterKeyWrapper(b"B" * 32, aes).unwrap_key(
            wrapped.ciphertext,
            wrapped.nonce,
            b"aad",
        )


def test_encryption_service_rejects_wrong_master_key_without_plaintext() -> None:
    aes = AESService()
    context = CryptoContext(
        file_id=uuid4(),
        owner_id=uuid4(),
        plaintext_size=12,
    )
    encrypted = EncryptionService(
        aes,
        MasterKeyWrapper(b"A" * 32, aes),
    ).encrypt_file(b"secret bytes", context)
    wrong_service = EncryptionService(
        aes,
        MasterKeyWrapper(b"B" * 32, aes),
    )

    with pytest.raises(CryptoIntegrityError):
        wrong_service.decrypt_file(
            encrypted.ciphertext,
            content_nonce=encrypted.content_nonce,
            wrapped_file_key=encrypted.wrapped_file_key,
            key_wrap_nonce=encrypted.key_wrap_nonce,
            content_algorithm=encrypted.content_algorithm,
            key_wrap_algorithm=encrypted.key_wrap_algorithm,
            crypto_version=encrypted.crypto_version,
            aad_version=encrypted.aad_version,
            context=context,
        )
