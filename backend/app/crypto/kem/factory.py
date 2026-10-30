"""Construct the exact Phase 7 allow-listed KEM registry."""

from app.crypto.kem.mlkem import (
    MLKEM1024Provider,
    MLKEM512Provider,
    MLKEM768Provider,
)
from app.crypto.kem.registry import KEMRegistry


def build_kem_registry() -> KEMRegistry:
    return KEMRegistry(
        (MLKEM512Provider(), MLKEM768Provider(), MLKEM1024Provider())
    )
