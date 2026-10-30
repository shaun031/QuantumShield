"""Explicit crypto-format dispatch profiles."""

from dataclasses import dataclass
from enum import StrEnum


class CryptoHandlerKind(StrEnum):
    LEGACY_MASTER = "LEGACY_MASTER"
    LEGACY_MLKEM = "LEGACY_MLKEM"
    CRYPTO_SUITE = "CRYPTO_SUITE"
    HYBRID_SUITE = "HYBRID_SUITE"


class UnsupportedCryptoVersionError(ValueError):
    pass


@dataclass(frozen=True)
class CryptoVersionHandler:
    crypto_version: int
    aad_version: int
    kind: CryptoHandlerKind


class CryptoVersionHandlerRegistry:
    def __init__(self, handlers: tuple[CryptoVersionHandler, ...]) -> None:
        self._handlers = {handler.crypto_version: handler for handler in handlers}
        if len(self._handlers) != len(handlers):
            raise ValueError("Duplicate crypto-version handler")

    def get(self, crypto_version: int, aad_version: int) -> CryptoVersionHandler:
        try:
            handler = self._handlers[crypto_version]
        except KeyError as exc:
            raise UnsupportedCryptoVersionError(
                f"Unsupported crypto version: {crypto_version}"
            ) from exc
        if handler.aad_version != aad_version:
            raise UnsupportedCryptoVersionError(
                f"Unsupported AAD version {aad_version} for crypto version {crypto_version}"
            )
        return handler


FILE_CRYPTO_VERSION_HANDLERS = CryptoVersionHandlerRegistry(
    (
        CryptoVersionHandler(1, 1, CryptoHandlerKind.LEGACY_MASTER),
        CryptoVersionHandler(2, 2, CryptoHandlerKind.LEGACY_MLKEM),
        CryptoVersionHandler(3, 3, CryptoHandlerKind.CRYPTO_SUITE),
        CryptoVersionHandler(4, 4, CryptoHandlerKind.HYBRID_SUITE),
    )
)
