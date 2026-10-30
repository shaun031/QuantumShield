"""Master-key configuration validation without secret disclosure."""

import base64

import pytest

from app.core.config import Settings


@pytest.mark.parametrize(
    "configured_value",
    ["not valid base64!", base64.urlsafe_b64encode(b"short").decode("ascii")],
)
def test_invalid_master_key_configuration_fails_safely(
    configured_value: str,
) -> None:
    configuration = Settings(master_key_base64=configured_value)

    with pytest.raises(
        ValueError,
        match=r"^Invalid MASTER_KEY_BASE64 configuration\.$",
    ) as error:
        _ = configuration.master_key_bytes

    assert configured_value not in str(error.value)


def test_valid_master_key_configuration_decodes_exactly_32_bytes() -> None:
    key = b"K" * 32
    configuration = Settings(
        master_key_base64=base64.urlsafe_b64encode(key).decode("ascii")
    )

    assert configuration.master_key_bytes == key


def test_phase7_rejects_unknown_or_mis_cased_security_level() -> None:
    with pytest.raises(
        ValueError,
    ):
        Settings(default_security_level="ADAPTIVE")
    with pytest.raises(ValueError):
        Settings(default_security_level="standard")


def test_standard_is_the_default_and_maps_to_mlkem768() -> None:
    configuration = Settings()
    assert configuration.default_security_level == "STANDARD"
    assert configuration.default_kem_algorithm == "ML-KEM-768"
