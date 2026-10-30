"""Safe public authenticity result; never exposes signature or private material."""

from typing import Literal

from pydantic import BaseModel

from app.services.signatures import VerificationResult


class SignatureVerificationResponse(BaseModel):
    status: Literal["VALID", "INVALID", "LEGACY_UNSIGNED"]
    scope: Literal["FILE", "SHARE"]
    algorithm: str | None = None
    profile_id: str | None = None
    signer_user_id: str | None = None

    @classmethod
    def from_result(cls, result: VerificationResult) -> "SignatureVerificationResponse":
        return cls(status=result.status.value, scope=result.scope,
                   algorithm=result.algorithm, profile_id=result.profile_id,
                   signer_user_id=result.signer_user_id)
