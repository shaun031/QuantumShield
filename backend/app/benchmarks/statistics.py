"""Unfiltered statistics for high-resolution wall-clock samples."""

from math import ceil
from statistics import mean, median, pstdev


def summarize(samples_ns: list[int]) -> dict[str, float | int]:
    if not samples_ns or any(value <= 0 for value in samples_ns):
        raise ValueError("Timing samples must be positive and nonempty")
    samples_ms = [value / 1_000_000 for value in samples_ns]
    ordered = sorted(samples_ms)
    return {
        "sample_count": len(samples_ms),
        "mean_ms": mean(samples_ms),
        "median_ms": median(samples_ms),
        "stddev_ms": pstdev(samples_ms),
        "min_ms": ordered[0],
        "max_ms": ordered[-1],
        "p95_ms": ordered[ceil(0.95 * len(ordered)) - 1],
    }
