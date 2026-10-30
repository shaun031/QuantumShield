"""Idempotently ensure the complete ML-KEM + X25519 keyset for existing users."""

import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.provision_mlkem_keys import main


if __name__ == "__main__":
    main()
