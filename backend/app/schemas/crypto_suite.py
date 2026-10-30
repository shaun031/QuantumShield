"""Public crypto-suite metadata without key material."""

from pydantic import BaseModel

from app.crypto.security_levels import SecurityLevel
from app.crypto.suites import CryptoSuiteStatus, SecurityArchitecture


class CryptoSuiteResponse(BaseModel):
    suite_id: str
    version: int
    security_level: SecurityLevel
    status: CryptoSuiteStatus
    content_aead: str
    kem: str
    kdf: str
    key_wrap: str
    description: str
    available: bool
    architecture: SecurityArchitecture
    classical_algorithm: str | None
