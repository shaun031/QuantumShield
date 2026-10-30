"""Local opaque-object storage used by versioned encrypted file workflows."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from uuid import uuid4


class InvalidStorageKeyError(ValueError):
    """Raised when an internal object key could escape the configured root."""


@dataclass(frozen=True)
class StagedDeletion:
    original_path: Path
    staged_path: Path


class LocalStorageService:
    """Store opaque object keys beneath one fixed local directory.

    The adapter treats all bytes as opaque. File services pass only AES-GCM
    ciphertext to it, keeping filesystem operations out of business services.
    """

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def resolve_path(self, object_key: str) -> Path:
        key = PurePosixPath(object_key)
        if key.is_absolute() or not key.parts or any(
            part in {"", ".", ".."} for part in key.parts
        ):
            raise InvalidStorageKeyError("Invalid internal storage key")

        resolved = self.root.joinpath(*key.parts).resolve()
        if not resolved.is_relative_to(self.root):
            raise InvalidStorageKeyError("Storage key escapes configured root")
        return resolved

    def save_bytes(self, data: bytes, object_key: str) -> None:
        target = self.resolve_path(object_key)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.{uuid4().hex}.part")

        try:
            with temporary.open("xb") as destination:
                destination.write(data)
                destination.flush()
                os.fsync(destination.fileno())

            temporary.replace(target)
        except Exception:
            temporary.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            raise

    def open_file(self, object_key: str) -> Path:
        path = self.resolve_path(object_key)
        if not path.is_file():
            raise FileNotFoundError
        return path

    def read_bytes(self, object_key: str) -> bytes:
        return self.open_file(object_key).read_bytes()

    def exists(self, object_key: str) -> bool:
        return self.resolve_path(object_key).is_file()

    def delete_file(self, object_key: str) -> bool:
        path = self.resolve_path(object_key)
        existed = path.is_file()
        path.unlink(missing_ok=True)
        self._remove_empty_parent(path.parent)
        return existed

    def stage_delete(self, object_key: str) -> StagedDeletion | None:
        original = self.resolve_path(object_key)
        if not original.is_file():
            return None
        staged = original.with_name(f".{original.name}.{uuid4().hex}.deleting")
        original.replace(staged)
        return StagedDeletion(original_path=original, staged_path=staged)

    def restore_staged_delete(self, staged: StagedDeletion | None) -> None:
        if staged is not None and staged.staged_path.is_file():
            staged.staged_path.replace(staged.original_path)

    def finalize_staged_delete(self, staged: StagedDeletion | None) -> None:
        if staged is None:
            return
        staged.staged_path.unlink(missing_ok=True)
        self._remove_empty_parent(staged.staged_path.parent)

    def _remove_empty_parent(self, directory: Path) -> None:
        if directory == self.root:
            return
        try:
            directory.rmdir()
        except OSError:
            pass
