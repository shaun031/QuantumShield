"""Write benchmark-only, secret-free JSON and flat CSV exports."""

import csv
import json
from pathlib import Path


CSV_FIELDS = (
    "run_id", "timestamp", "benchmark_type", "scenario_id", "suite_id",
    "algorithm", "architecture", "security_level", "post_quantum_resistant",
    "operation", "file_size_bytes", "recipient_count", "sample_count", "warmups",
    "mean_ms", "median_ms", "stddev_ms", "min_ms", "max_ms", "p95_ms",
    "public_key_bytes", "private_key_bytes", "kem_ciphertext_bytes",
    "signature_bytes", "ephemeral_public_key_bytes", "wrapped_key_bytes",
    "metadata_overhead_bytes", "ciphertext_bytes", "total_package_bytes",
    "overhead_bytes", "overhead_percent", "peak_python_allocation_bytes",
)


def export_run(run: dict, directory: Path) -> dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": directory / "results.json",
        "csv": directory / "results.csv",
        "samples": directory / "samples.csv",
    }
    # Artifacts contain no key material or source plaintext.
    paths["json"].write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    with paths["csv"].open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for row in run["results"]:
            writer.writerow({key: (run[key] if key in {"run_id", "timestamp"} else row.get(key))
                             for key in CSV_FIELDS})
    with paths["samples"].open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("run_id", "scenario_id", "iteration", "elapsed_ns", "elapsed_ms"))
        for row in run["results"]:
            for index, elapsed_ns in enumerate(row["samples_ns"], 1):
                writer.writerow((run["run_id"], row["scenario_id"], index,
                                 elapsed_ns, elapsed_ns / 1_000_000))
    return paths
