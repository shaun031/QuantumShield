"""Explicitly create a local .env once, without displaying or replacing secrets."""

import base64
import re
import secrets
from pathlib import Path

from dotenv import dotenv_values


BACKEND_DIR = Path(__file__).resolve().parents[1]


def create_environment(backend_dir: Path = BACKEND_DIR) -> Path:
    destination = backend_dir / ".env"
    if destination.exists():
        raise FileExistsError("Local .env already exists; no values were replaced.")
    template_path = backend_dir / ".env.example"
    template = template_path.read_text(encoding="utf-8")
    values = dotenv_values(template_path, interpolate=False)
    for name in ("DATABASE_URL", "SECRET_KEY", "MASTER_KEY_BASE64"):
        if not values.get(name):
            raise ValueError(f"Template is missing required configuration: {name}")
    # Do not generate replacement keys for a directory containing persistent objects.
    configured_storage = Path(values.get("STORAGE_PATH") or "storage/files")
    storage = configured_storage if configured_storage.is_absolute() else backend_dir / configured_storage
    if storage.exists() and any(path.is_file() and path.name != ".gitkeep"
                                for path in storage.rglob("*")):
        raise ValueError("Existing storage objects found; restore the original .env/master key first.")
    replacements = {
        "SECRET_KEY": secrets.token_urlsafe(64),
        "MASTER_KEY_BASE64": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
    }
    for name, value in replacements.items():
        pattern = rf"^{name}=.*$"
        if len(re.findall(pattern, template, flags=re.MULTILINE)) != 1:
            raise ValueError(f"Template must contain exactly one {name} assignment")
        template = re.sub(pattern, lambda _: f"{name}={value}", template, flags=re.MULTILINE)
    header = (
        "# Local development configuration. Keep private and outside version control.\n"
        "# Application secrets were generated once; do not replace them for existing data.\n"
        "# Enter the real PostgreSQL password in DATABASE_URL before database commands.\n"
        "# If that database contains older protected keys/files, restore its ORIGINAL master key.\n\n"
    )
    # Exclusive creation also prevents a concurrent invocation from replacing keys.
    with destination.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(header + template)
    return destination


def main() -> int:
    try:
        destination = create_environment()
    except (OSError, ValueError) as error:
        # Only known non-secret setup errors are emitted; never dump file contents.
        if isinstance(error, FileExistsError):
            print("Local .env already exists; no values were replaced.")
        elif isinstance(error, ValueError):
            print(str(error))
        else:
            print("Unable to read the template or create the local .env; check file permissions.")
        return 1
    print(f"Created {destination} with securely generated development application secrets.")
    print("Master key: valid Base64 encoding of 32 random bytes. Secret values are not displayed.")
    print("Set the PostgreSQL password locally in DATABASE_URL before running migrations.")
    print("Existing encrypted PostgreSQL data requires its original master key.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
