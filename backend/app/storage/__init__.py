"""Opaque storage adapters used by encrypted file workflows."""

"""Storage adapters for opaque file objects."""

from app.storage.local import (
    InvalidStorageKeyError,
    LocalStorageService,
)

__all__ = [
    "InvalidStorageKeyError",
    "LocalStorageService",
]
