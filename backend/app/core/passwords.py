"""Argon2id password hashing through the maintained pwdlib abstraction."""

import secrets

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError


_password_hash = PasswordHash.recommended()
_dummy_password_hash = _password_hash.hash(secrets.token_urlsafe(32))


def hash_password(password: str) -> str:
    """Create a salted Argon2id password hash."""

    return _password_hash.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify through pwdlib without exposing parsing/verification errors."""

    try:
        return _password_hash.verify(password, password_hash)
    except UnknownHashError:
        return False


def perform_dummy_password_verification(password: str) -> None:
    """Reduce the timing distinction between unknown users and bad passwords."""

    verify_password(password, _dummy_password_hash)

