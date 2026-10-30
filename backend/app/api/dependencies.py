"""Reusable service and authenticated-user dependencies."""

from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.core.auth import InvalidAccessTokenError, decode_access_token
from app.core.config import settings
from app.crypto.aes import AESService
from app.crypto.encryption import EncryptionService
from app.crypto.kdf import HKDFService
from app.crypto.key_agreement import X25519Provider
from app.crypto.hybrid_key_protection import HybridKeyProtector
from app.crypto.aead import AEADProvider
from app.crypto.kem.factory import build_kem_registry
from app.crypto.kem_key_protection import MLKEMFileKeyProtector
from app.crypto.key_wrap import AESGCMKeyWrapProvider, KeyWrapProvider
from app.crypto.key_protection import MasterKeyWrapper
from app.crypto.provider_registry import ProviderRegistry
from app.crypto.secret_protection import SecretProtectionService
from app.crypto.share_key_protection import MLKEMShareKeyProtector
from app.crypto.kdf import KDFProvider
from app.crypto.suite_factory import build_crypto_suite_registry
from app.crypto.suite_key_protection import SuiteFileKeyProtector, SuiteShareKeyProtector
from app.crypto.suites import CryptoSuiteRegistry
from app.crypto.security_levels import SecurityLevelPolicy
from app.crypto.signature_profiles import build_signature_profile_registry
from app.db.session import get_db
from app.models.user import User
from app.repositories.user import UserRepository
from app.services.auth import AuthService
from app.services.crypto_keys import CryptoKeyService
from app.services.files import FileService
from app.services.security_policy import SecurityPolicyEngine
from app.services.shares import ShareService
from app.services.signatures import SignatureService
from app.storage.local import LocalStorageService


oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.api_prefix}/auth/login",
)


_local_storage = LocalStorageService(settings.storage_directory)
_aes_service = AESService()
_kem_registry = build_kem_registry()
_kem_registry.assert_all_available()
_x25519_provider = X25519Provider()
_x25519_provider.self_test()
_signature_profiles = build_signature_profile_registry()
_kdf_service = HKDFService()
_key_wrap_service = AESGCMKeyWrapProvider(_aes_service)
_aead_registry: ProviderRegistry[AEADProvider] = ProviderRegistry(
    "AEAD", (_aes_service,)
)
_kdf_registry: ProviderRegistry[KDFProvider] = ProviderRegistry(
    "KDF", (_kdf_service,)
)
_key_wrap_registry: ProviderRegistry[KeyWrapProvider] = ProviderRegistry(
    "key-wrap", (_key_wrap_service,)
)
_crypto_suite_registry = build_crypto_suite_registry(
    _aead_registry,
    _kem_registry,
    _kdf_registry,
    _key_wrap_registry,
)
_crypto_suite_registry.assert_all_available()
_suite_file_key_protector = SuiteFileKeyProtector(_crypto_suite_registry)
_suite_share_key_protector = SuiteShareKeyProtector(_crypto_suite_registry)
_hybrid_key_protector = HybridKeyProtector(_crypto_suite_registry, _x25519_provider)
_secret_protection_service = SecretProtectionService(
    settings.master_key_bytes,
    _aes_service,
)
_encryption_service = EncryptionService(
    _aes_service,
    MasterKeyWrapper(settings.master_key_bytes, _aes_service),
    MLKEMFileKeyProtector(_kem_registry, _kdf_service, _aes_service),
    _crypto_suite_registry,
    _suite_file_key_protector,
    _hybrid_key_protector,
)
_share_key_protector = MLKEMShareKeyProtector(
    _kem_registry,
    _kdf_service,
    _aes_service,
)
_security_policy_engine = SecurityPolicyEngine(
    level_policy=SecurityLevelPolicy(suite_registry=_crypto_suite_registry)
)


def get_crypto_key_service(
    database: Annotated[Session, Depends(get_db)],
) -> CryptoKeyService:
    return CryptoKeyService(
        database,
        _kem_registry,
        _secret_protection_service,
        settings.default_kem_algorithm,
        _x25519_provider,
        _signature_profiles,
        settings.default_signature_algorithm,
    )


def get_signature_service(
    database: Annotated[Session, Depends(get_db)],
    crypto_keys: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
) -> SignatureService:
    return SignatureService(database, crypto_keys, _signature_profiles,
                            settings.default_signature_algorithm)


def get_auth_service(
    database: Annotated[Session, Depends(get_db)],
    crypto_keys: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
) -> AuthService:
    return AuthService(database, crypto_keys)


def get_storage_service() -> LocalStorageService:
    return _local_storage


def get_encryption_service() -> EncryptionService:
    return _encryption_service


def get_crypto_suite_registry() -> CryptoSuiteRegistry:
    return _crypto_suite_registry


def get_security_policy_engine() -> SecurityPolicyEngine:
    return _security_policy_engine


def get_file_service(
    database: Annotated[Session, Depends(get_db)],
    storage: Annotated[LocalStorageService, Depends(get_storage_service)],
    encryption: Annotated[EncryptionService, Depends(get_encryption_service)],
    crypto_keys: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
    signatures: Annotated[SignatureService, Depends(get_signature_service)],
) -> FileService:
    return FileService(
        database,
        storage,
        encryption,
        crypto_keys,
        settings.max_upload_size_bytes,
        _security_policy_engine,
        signatures,
    )


def get_share_service(
    database: Annotated[Session, Depends(get_db)],
    files: Annotated[FileService, Depends(get_file_service)],
    crypto_keys: Annotated[CryptoKeyService, Depends(get_crypto_key_service)],
) -> ShareService:
    return ShareService(
        database,
        files,
        crypto_keys,
        _share_key_protector,
        _crypto_suite_registry,
        _suite_share_key_protector,
        _hybrid_key_protector,
    )


def authentication_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    database: Annotated[Session, Depends(get_db)],
) -> User:
    try:
        token_payload = decode_access_token(token)
        user_id = UUID(token_payload.sub)
    except (InvalidAccessTokenError, ValueError) as exc:
        raise authentication_error() from exc

    user = UserRepository(database).get_by_id(user_id)
    if user is None:
        raise authentication_error()
    return user


def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user account",
        )
    return current_user


CurrentActiveUser = Annotated[User, Depends(get_current_active_user)]

