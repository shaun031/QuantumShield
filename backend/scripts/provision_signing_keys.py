"""Provision missing ML-DSA signing identities for existing users, idempotently."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from app.core.config import settings
from app.crypto.aes import AESService
from app.crypto.kem.factory import build_kem_registry
from app.crypto.secret_protection import SecretProtectionService
from app.crypto.signature_profiles import build_signature_profile_registry
from app.db.session import SessionLocal
from app.models.user import User
from app.services.crypto_keys import CryptoKeyService


def main() -> None:
    with SessionLocal() as session:
        service = CryptoKeyService(
            session, build_kem_registry(),
            SecretProtectionService(settings.master_key_bytes, AESService()),
            settings.default_kem_algorithm,
            signature_profiles=build_signature_profile_registry(),
            default_signature_algorithm=settings.default_signature_algorithm,
        )
        checked = created = 0
        for user in list(session.scalars(select(User).order_by(User.id))):
            checked += 1
            if service.keys.get_active(user.id, settings.default_signature_algorithm) is None:
                service.ensure_signing_key_for_user(user)
                created += 1
    print(f"Users checked: {checked}")
    print(f"Signing keys created: {created}")


if __name__ == "__main__":
    main()
