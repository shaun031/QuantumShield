"""Explicit user-key purposes; never infer permission from a caller's label."""

from enum import StrEnum

from app.crypto.identifiers import ML_DSA_44, ML_DSA_65, ML_DSA_87, ML_KEM_512, ML_KEM_768, ML_KEM_1024, X25519


class KeyPurpose(StrEnum):
    KEM = "KEM"
    KEY_AGREEMENT = "KEY_AGREEMENT"
    SIGNATURE = "SIGNATURE"


PURPOSE_BY_ALGORITHM = {
    ML_KEM_512: KeyPurpose.KEM,
    ML_KEM_768: KeyPurpose.KEM,
    ML_KEM_1024: KeyPurpose.KEM,
    X25519: KeyPurpose.KEY_AGREEMENT,
    ML_DSA_44: KeyPurpose.SIGNATURE,
    ML_DSA_65: KeyPurpose.SIGNATURE,
    ML_DSA_87: KeyPurpose.SIGNATURE,
}
