"""Bounded, versioned benchmark profiles and stable synthetic scenarios."""

from dataclasses import dataclass


MAX_ITERATIONS = 100
MAX_FILE_SIZE = 25 * 1024 * 1024
MAX_RECIPIENTS = 25
MAX_WORKLOAD_BYTES = 8 * 1024 * 1024 * 1024
SCHEMA_VERSION = 1
BASELINE_ID = "BENCH-X25519-V1"


@dataclass(frozen=True)
class Profile:
    iterations: int
    warmups: int
    file_sizes: tuple[int, ...]
    recipient_counts: tuple[int, ...]


PROFILES = {
    "quick": Profile(3, 1, (1024, 100 * 1024, 1024 * 1024), (1, 5)),
    "standard": Profile(20, 5, (1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024, 25 * 1024 * 1024), (1, 5, 10)),
    "full": Profile(30, 5, (1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024, 25 * 1024 * 1024), (1, 5, 10, 25)),
}


def parse_size(value: str) -> int:
    item = value.strip().upper()
    for suffix, scale in (("MB", 1024 * 1024), ("KB", 1024), ("B", 1)):
        if item.endswith(suffix):
            amount = item[:-len(suffix)]
            if not amount.isdigit():
                break
            size = int(amount) * scale
            if 0 < size <= MAX_FILE_SIZE:
                return size
            break
    raise ValueError(f"File size must be 1B through 25MB: {value}")


def validate_config(iterations: int, warmups: int, sizes: tuple[int, ...],
                    recipients: tuple[int, ...]) -> None:
    if not 1 <= iterations <= MAX_ITERATIONS or not 0 <= warmups <= 20:
        raise ValueError("Iterations must be 1-100 and warmups 0-20")
    if not sizes or any(not 0 < size <= MAX_FILE_SIZE for size in sizes):
        raise ValueError("File sizes must be 1B through 25MB")
    if not recipients or any(not 1 <= count <= MAX_RECIPIENTS for count in recipients):
        raise ValueError("Recipient counts must be 1-25")
