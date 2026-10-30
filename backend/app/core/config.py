"""Validated application settings loaded from environment variables."""

import base64
import binascii
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BACKEND_DIR = Path(__file__).resolve().parents[2]
ENV_FILE = BACKEND_DIR / ".env"


class Settings(BaseSettings):
    """Central configuration for application infrastructure and authentication."""

    model_config = SettingsConfigDict(
        env_file=ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # Configuration tracebacks must not echo invalid secrets or DB credentials.
        hide_input_in_errors=True,
    )

    app_name: str = Field(default="QuantumShield", min_length=1)
    app_env: str = Field(default="development", min_length=1)
    debug: bool = False
    api_prefix: str = "/api"

    database_url: str = Field(min_length=1, repr=False)

    frontend_url: str = "http://localhost:5173"
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    secret_key: SecretStr = Field(min_length=32, repr=False)
    access_token_expire_minutes: int = Field(default=30, ge=1)
    jwt_algorithm: Literal["HS256"] = "HS256"
    master_key_base64: SecretStr
    default_security_level: Literal["LOW", "STANDARD", "HIGH"] = "STANDARD"
    default_signature_algorithm: Literal["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"] = "ML-DSA-65"

    storage_path: Path = Path("storage/files")
    max_upload_size_mb: int = Field(default=25, ge=1, le=1024)
    log_level: str = "INFO"

    @field_validator("api_prefix")
    @classmethod
    def validate_api_prefix(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/"):
            raise ValueError("API_PREFIX must start with '/'")
        if len(value) > 1:
            value = value.rstrip("/")
        return value

    @field_validator("frontend_url")
    @classmethod
    def normalize_frontend_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("FRONTEND_URL must be an HTTP(S) origin")
        return value

    @field_validator("log_level")
    @classmethod
    def normalize_log_level(cls, value: str) -> str:
        normalized = value.strip().upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return normalized

    @property
    def allowed_origins(self) -> tuple[str, ...]:
        """Return unique, exact CORS origins without wildcard expansion."""

        candidates = [self.frontend_url, *self.cors_origins.split(",")]
        normalized = (origin.strip().rstrip("/") for origin in candidates)
        return tuple(dict.fromkeys(origin for origin in normalized if origin))

    @property
    def storage_directory(self) -> Path:
        """Resolve a relative storage path from the backend directory."""

        if self.storage_path.is_absolute():
            return self.storage_path.resolve()
        return (BACKEND_DIR / self.storage_path).resolve()

    @property
    def max_upload_size_bytes(self) -> int:
        """Return the configured upload ceiling in bytes."""

        return self.max_upload_size_mb * 1024 * 1024

    @property
    def default_kem_algorithm(self) -> str:
        from app.crypto.security_levels import SecurityLevelPolicy

        return SecurityLevelPolicy().get_algorithm(self.default_security_level)

    @property
    def master_key_bytes(self) -> bytes:
        """Decode and validate the 256-bit application master key safely."""

        try:
            decoded = base64.b64decode(
                self.master_key_base64.get_secret_value().strip(),
                altchars=b"-_",
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise ValueError("Invalid MASTER_KEY_BASE64 configuration.") from exc
        if len(decoded) != 32:
            raise ValueError("Invalid MASTER_KEY_BASE64 configuration.")
        return decoded


@lru_cache
def get_settings() -> Settings:
    """Load settings once per process without exposing secret values."""

    return Settings()


settings = get_settings()
