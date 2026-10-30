"""Idempotently provision missing ML-KEM and X25519 user keys."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select

from app.core.config import settings
from app.crypto.aes import AESService
from app.crypto.kem.factory import build_kem_registry
from app.crypto.secret_protection import SecretProtectionService
from app.db.session import SessionLocal
from app.models.user import User
from app.services.crypto_keys import CryptoKeyService


def main() -> None:
    registry = build_kem_registry()
    registry.assert_all_available()
    aes = AESService()
    protection = SecretProtectionService(settings.master_key_bytes, aes)
    users_seen = 0
    keys_created = 0

    with SessionLocal() as session:
        service = CryptoKeyService(
            session,
            registry,
            protection,
            settings.default_kem_algorithm,
        )
        for user in session.scalars(select(User).order_by(User.id)):
            users_seen += 1
            before = len(service.list_active_for_user(user.id))
            after = len(service.ensure_keyset_for_user(user))
            keys_created += after - before

    print(f"Users checked: {users_seen}")
    print(f"Missing cryptographic keys created: {keys_created}")


if __name__ == "__main__":
    main()
