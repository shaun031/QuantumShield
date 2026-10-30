"""Regression checks for durable local environment setup and config loading."""

import base64
from pathlib import Path

import pytest
from dotenv import dotenv_values
from pydantic import ValidationError
from sqlalchemy.engine import make_url

from app.core.config import BACKEND_DIR, ENV_FILE, Settings
from scripts.init_dev_env import create_environment


def copy_template(directory: Path) -> None:
    (directory / ".env.example").write_text(
        (BACKEND_DIR / ".env.example").read_text(encoding="utf-8"), encoding="utf-8"
    )


def test_environment_template_covers_actual_settings() -> None:
    names = set(dotenv_values(BACKEND_DIR / ".env.example", interpolate=False))
    assert {name.upper() for name in Settings.model_fields} == names
    assert dotenv_values(BACKEND_DIR / ".env.example")["SECRET_KEY"] == "CHANGE_ME"
    assert dotenv_values(BACKEND_DIR / ".env.example")["MASTER_KEY_BASE64"] == "CHANGE_ME"
    assert make_url(dotenv_values(BACKEND_DIR / ".env.example")["DATABASE_URL"]).password in {
        "CHANGE_ME", "PASSWORD_HERE"
    }


def test_initializer_generates_valid_unique_development_secrets(tmp_path: Path) -> None:
    copy_template(tmp_path)
    destination = create_environment(tmp_path)
    values = dotenv_values(destination, interpolate=False)
    assert len(values["SECRET_KEY"]) >= 86
    assert len(base64.b64decode(values["MASTER_KEY_BASE64"], validate=True)) == 32
    assert values["DATABASE_URL"] == dotenv_values(tmp_path / ".env.example")["DATABASE_URL"]
    other = tmp_path / "independent"
    other.mkdir()
    copy_template(other)
    second = dotenv_values(create_environment(other), interpolate=False)
    assert values["SECRET_KEY"] != second["SECRET_KEY"]
    assert values["MASTER_KEY_BASE64"] != second["MASTER_KEY_BASE64"]


def test_initializer_never_replaces_existing_secrets(tmp_path: Path) -> None:
    copy_template(tmp_path)
    destination = create_environment(tmp_path)
    original = destination.read_bytes()
    with pytest.raises(FileExistsError):
        create_environment(tmp_path)
    assert destination.read_bytes() == original


def test_initializer_refuses_existing_persistent_storage(tmp_path: Path) -> None:
    copy_template(tmp_path)
    storage = tmp_path / "storage" / "files"
    storage.mkdir(parents=True)
    (storage / "encrypted-object").write_bytes(b"test-only encrypted-object fixture")
    with pytest.raises(ValueError, match="restore the original"):
        create_environment(tmp_path)
    assert not (tmp_path / ".env").exists()


def test_absolute_env_loading_and_environment_precedence(tmp_path: Path, monkeypatch) -> None:
    assert ENV_FILE == BACKEND_DIR / ".env" and ENV_FILE.is_absolute()
    copy_template(tmp_path)
    destination = create_environment(tmp_path)
    for field in Settings.model_fields:
        monkeypatch.delenv(field.upper(), raising=False)
    elsewhere = tmp_path / "another-working-directory"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    loaded = Settings(_env_file=destination)
    assert len(loaded.master_key_bytes) == 32
    assert loaded.database_url.endswith("@127.0.0.1:5433/quantumshield")
    assert loaded.storage_directory == BACKEND_DIR / "storage" / "files"
    replacement = "explicit-test-environment-secret-at-least-32-characters"
    monkeypatch.setenv("SECRET_KEY", replacement)
    assert Settings(_env_file=destination).secret_key.get_secret_value() == replacement


@pytest.mark.parametrize("required_field", ["database_url", "secret_key", "master_key_base64"])
def test_security_settings_remain_required(required_field: str, monkeypatch) -> None:
    for field in ("DATABASE_URL", "SECRET_KEY", "MASTER_KEY_BASE64"):
        monkeypatch.delenv(field, raising=False)
    supplied = {
        "database_url": "sqlite+pysqlite:///:memory:",
        "secret_key": "explicit-required-field-test-secret-long-enough",
        "master_key_base64": base64.b64encode(b"X" * 32).decode("ascii"),
    }
    supplied.pop(required_field)
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, **supplied)
    assert any(item["loc"] == (required_field,) and item["type"] == "missing"
               for item in error.value.errors())


def test_configuration_validation_errors_do_not_echo_secrets() -> None:
    invalid_secret = "short-secret-fixture"
    with pytest.raises(ValidationError) as error:
        Settings(_env_file=None, secret_key=invalid_secret)
    assert invalid_secret not in str(error.value)
