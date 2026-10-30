"""Legacy Phase 4 master-key protection for version-1 file AES keys."""

from app.crypto.aes import AES_KEY_BYTES, AESService, AeadCiphertext
from app.crypto.identifiers import MASTER_AES_256_GCM


class MasterKeyWrapper:
    algorithm_id = MASTER_AES_256_GCM

    def __init__(self, master_key: bytes, aes: AESService) -> None:
        if len(master_key) != AES_KEY_BYTES:
            raise ValueError("The application master key must be exactly 32 bytes")
        self._master_key = master_key
        self._aes = aes

    def wrap_key(self, file_key: bytes, aad: bytes) -> AeadCiphertext:
        if len(file_key) != AES_KEY_BYTES:
            raise ValueError("A file key must be exactly 32 bytes")
        return self._aes.encrypt(file_key, self._master_key, aad)

    def unwrap_key(self, wrapped_key: bytes, nonce: bytes, aad: bytes) -> bytes:
        return self._aes.decrypt(wrapped_key, self._master_key, nonce, aad)
