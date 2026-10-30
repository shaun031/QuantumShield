"""Approved suite specifications; the only level-to-algorithm composition table."""

from dataclasses import dataclass

from app.crypto.identifiers import (
    AES_256_GCM,
    HKDF_SHA256,
    KEK_AES_256_GCM,
    ML_KEM_1024,
    ML_KEM_512,
    ML_KEM_768,
    QS_PQ_1024_V1,
    QS_PQ_512_V1,
    QS_PQ_768_V1,
    QS_HYBRID_512_V1,
    QS_HYBRID_768_V1,
    QS_HYBRID_1024_V1,
    X25519,
)


@dataclass(frozen=True)
class CryptoSuiteSpec:
    suite_id: str
    version: int
    security_level: str
    content_aead: str
    kem: str
    kdf: str
    key_wrap: str
    description: str
    architecture: str = "PQ_ONLY"
    classical_algorithm: str | None = None


APPROVED_SUITE_SPECS = (
    CryptoSuiteSpec(
        suite_id=QS_PQ_512_V1,
        version=1,
        security_level="LOW",
        content_aead=AES_256_GCM,
        kem=ML_KEM_512,
        kdf=HKDF_SHA256,
        key_wrap=KEK_AES_256_GCM,
        description="AES-256-GCM with ML-KEM-512 and HKDF-SHA256",
    ),
    CryptoSuiteSpec(
        suite_id=QS_PQ_768_V1,
        version=1,
        security_level="STANDARD",
        content_aead=AES_256_GCM,
        kem=ML_KEM_768,
        kdf=HKDF_SHA256,
        key_wrap=KEK_AES_256_GCM,
        description="AES-256-GCM with ML-KEM-768 and HKDF-SHA256",
    ),
    CryptoSuiteSpec(
        suite_id=QS_PQ_1024_V1,
        version=1,
        security_level="HIGH",
        content_aead=AES_256_GCM,
        kem=ML_KEM_1024,
        kdf=HKDF_SHA256,
        key_wrap=KEK_AES_256_GCM,
        description="AES-256-GCM with ML-KEM-1024 and HKDF-SHA256",
    ),
    CryptoSuiteSpec(QS_HYBRID_512_V1, 1, "LOW", AES_256_GCM, ML_KEM_512, HKDF_SHA256, KEK_AES_256_GCM, "X25519 + ML-KEM-512 hybrid", "HYBRID", X25519),
    CryptoSuiteSpec(QS_HYBRID_768_V1, 1, "STANDARD", AES_256_GCM, ML_KEM_768, HKDF_SHA256, KEK_AES_256_GCM, "X25519 + ML-KEM-768 hybrid", "HYBRID", X25519),
    CryptoSuiteSpec(QS_HYBRID_1024_V1, 1, "HIGH", AES_256_GCM, ML_KEM_1024, HKDF_SHA256, KEK_AES_256_GCM, "X25519 + ML-KEM-1024 hybrid", "HYBRID", X25519),
)

SUITE_SPEC_BY_ID = {spec.suite_id: spec for spec in APPROVED_SUITE_SPECS}
SUITE_SPEC_BY_LEVEL = {spec.security_level: spec for spec in APPROVED_SUITE_SPECS if spec.architecture == "PQ_ONLY"}
