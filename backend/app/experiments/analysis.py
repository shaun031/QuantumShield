"""Paired, sign-preserving calculations; no p-values or discarded samples."""

from collections import Counter, defaultdict
from math import sqrt
from statistics import mean, median, pstdev

from app.benchmarks.statistics import summarize


def savings_percent(adaptive: float, fixed: float) -> float:
    if fixed <= 0:
        raise ValueError("Fixed-HIGH denominator must be positive")
    return (fixed - adaptive) / fixed * 100


def paired_difference(adaptive_ns: list[int], fixed_ns: list[int]) -> dict:
    if not adaptive_ns or len(adaptive_ns) != len(fixed_ns):
        raise ValueError("Paired samples must have the same nonzero length")
    differences_ms = [(fixed - adaptive) / 1_000_000
                      for adaptive, fixed in zip(adaptive_ns, fixed_ns)]
    center = mean(differences_ms)
    stddev = pstdev(differences_ms)
    half_width = 1.96 * stddev / sqrt(len(differences_ms))
    return {
        "mean_difference_ms": center,
        "median_difference_ms": median(differences_ms),
        "stddev_difference_ms": stddev,
        "confidence_interval_95_ms": [center - half_width, center + half_width],
        "ci_method": "normal approximation of paired mean; descriptive, not a significance test",
    }


def summarize_scenario(scenario: dict, pairs: list[dict], adaptive_suite: str,
                       fixed_suite: str, policy_version: str,
                       decision_reasons: list[str], policy_compliant: bool) -> dict:
    if not pairs or not policy_compliant:
        raise ValueError("Incomplete or policy-violating scenario")
    metrics = ("crypto_total", "local_transfer_total", "file_encrypt", "file_decrypt",
               "key_protect", "key_recover", "share_create", "download_decrypt")
    result = {
        **scenario, "adaptive_suite": adaptive_suite, "fixed_suite": fixed_suite,
        "policy_version": policy_version, "decision_reasons": decision_reasons,
        "policy_compliant": policy_compliant, "sample_count": len(pairs),
        "execution_order": "alternating by scenario and iteration",
    }
    for metric in metrics:
        adaptive = [pair["adaptive"][f"{metric}_ns"] for pair in pairs]
        fixed = [pair["fixed_high"][f"{metric}_ns"] for pair in pairs]
        adaptive_stats, fixed_stats = summarize(adaptive), summarize(fixed)
        result[metric] = {
            "adaptive": adaptive_stats,
            "fixed_high": fixed_stats,
            "savings_percent": savings_percent(adaptive_stats["mean_ms"], fixed_stats["mean_ms"]),
            "paired_difference": paired_difference(adaptive, fixed),
        }
    first = pairs[0]
    for size_metric in ("metadata_bytes", "kem_ciphertext_bytes", "public_key_bytes",
                        "total_package_bytes", "peak_python_allocation_bytes"):
        adaptive = first["adaptive"][size_metric]
        fixed = first["fixed_high"][size_metric]
        result[size_metric] = {
            "adaptive": adaptive, "fixed_high": fixed,
            "savings_percent": savings_percent(adaptive, fixed) if fixed > 0 else 0.0,
        }
    return result


def _aggregate_group(rows: list[dict]) -> dict:
    if not rows:
        raise ValueError("Cannot aggregate an empty group")
    adaptive = mean(row["crypto_total"]["adaptive"]["mean_ms"] for row in rows)
    fixed = mean(row["crypto_total"]["fixed_high"]["mean_ms"] for row in rows)
    adaptive_meta = sum(row["metadata_bytes"]["adaptive"] for row in rows)
    fixed_meta = sum(row["metadata_bytes"]["fixed_high"] for row in rows)
    return {
        "scenario_count": len(rows), "adaptive_mean_crypto_ms": adaptive,
        "fixed_mean_crypto_ms": fixed, "time_savings_percent": savings_percent(adaptive, fixed),
        "adaptive_metadata_bytes": adaptive_meta, "fixed_metadata_bytes": fixed_meta,
        "metadata_savings_percent": savings_percent(adaptive_meta, fixed_meta),
        "adaptive_median_crypto_ms": median(row["crypto_total"]["adaptive"]["median_ms"] for row in rows),
        "fixed_median_crypto_ms": median(row["crypto_total"]["fixed_high"]["median_ms"] for row in rows),
        "adaptive_p95_crypto_ms": mean(row["crypto_total"]["adaptive"]["p95_ms"] for row in rows),
        "fixed_p95_crypto_ms": mean(row["crypto_total"]["fixed_high"]["p95_ms"] for row in rows),
        "mean_share_savings_percent": mean(row["share_create"]["savings_percent"] for row in rows),
        "policy_compliance_rate": sum(bool(row["policy_compliant"]) for row in rows) / len(rows),
    }


def aggregate_results(rows: list[dict]) -> dict:
    if not rows:
        raise ValueError("No completed scenario results")
    by_architecture: dict[str, list] = defaultdict(list)
    by_level: dict[str, list] = defaultdict(list)
    by_size: dict[str, list] = defaultdict(list)
    by_architecture_and_size: dict[str, list] = defaultdict(list)
    level_counts: Counter = Counter()
    suite_counts: Counter = Counter()
    for row in rows:
        by_architecture[row["architecture"]].append(row)
        by_level[row["adaptive_level"]].append(row)
        by_size[str(row["file_size_bytes"])].append(row)
        by_architecture_and_size[f"{row['architecture']}:{row['file_size_bytes']}"].append(row)
        level_counts[row["adaptive_level"]] += 1
        suite_counts[row["adaptive_suite"]] += 1
    return {
        "overall": _aggregate_group(rows),
        "by_architecture": {name: _aggregate_group(group) for name, group in by_architecture.items()},
        "by_adaptive_level": {name: _aggregate_group(group) for name, group in by_level.items()},
        "by_file_size": {name: _aggregate_group(group) for name, group in by_size.items()},
        "by_architecture_and_file_size": {
            name: _aggregate_group(group) for name, group in by_architecture_and_size.items()
        },
        "adaptive_level_distribution": {
            name: {"count": count, "percent": count / len(rows) * 100}
            for name, count in sorted(level_counts.items())
        },
        "adaptive_suite_distribution": dict(sorted(suite_counts.items())),
    }
