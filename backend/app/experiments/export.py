"""Flat research exports; do not mutate, filter, or invent measurements."""

import csv
import json
from pathlib import Path


SUMMARY_FIELDS = (
    "experiment_run_id", "scenario_id", "architecture", "file_size_bytes",
    "sensitivity", "document_category", "recipient_count", "adaptive_level",
    "adaptive_suite", "fixed_suite", "policy_compliant", "sample_count",
    "adaptive_mean_crypto_ms", "fixed_mean_crypto_ms", "adaptive_median_crypto_ms",
    "fixed_median_crypto_ms", "adaptive_p95_crypto_ms", "fixed_p95_crypto_ms",
    "time_savings_percent", "mean_paired_difference_ms", "ci95_lower_ms", "ci95_upper_ms",
    "adaptive_mean_share_ms", "fixed_mean_share_ms", "share_savings_percent",
    "adaptive_mean_download_ms", "fixed_mean_download_ms",
    "adaptive_mean_local_transfer_ms", "fixed_mean_local_transfer_ms",
    "adaptive_metadata_bytes", "fixed_metadata_bytes", "metadata_savings_percent",
    "adaptive_kem_ciphertext_bytes", "fixed_kem_ciphertext_bytes",
    "adaptive_public_key_bytes", "fixed_public_key_bytes",
    "adaptive_total_package_bytes", "fixed_total_package_bytes",
    "adaptive_peak_python_allocation_bytes", "fixed_peak_python_allocation_bytes",
)

RAW_FIELDS = (
    "experiment_run_id", "scenario_id", "iteration", "execution_order", "condition",
    "suite_id", "file_size_bytes", "recipient_count", "crypto_total_ms",
    "local_transfer_total_ms", "share_create_ms", "download_decrypt_ms",
    "file_encrypt_ms", "file_decrypt_ms", "key_protect_ms", "key_recover_ms",
    "metadata_bytes", "kem_ciphertext_bytes", "public_key_bytes",
    "total_package_bytes", "peak_python_allocation_bytes",
)


def _summary_row(run_id: str, row: dict) -> dict:
    crypto = row["crypto_total"]
    paired = crypto["paired_difference"]
    return {
        "experiment_run_id": run_id,
        **{key: row[key] for key in (
            "scenario_id", "architecture", "file_size_bytes", "sensitivity",
            "document_category", "recipient_count", "adaptive_level", "adaptive_suite",
            "fixed_suite", "policy_compliant", "sample_count")},
        "adaptive_mean_crypto_ms": crypto["adaptive"]["mean_ms"],
        "fixed_mean_crypto_ms": crypto["fixed_high"]["mean_ms"],
        "adaptive_median_crypto_ms": crypto["adaptive"]["median_ms"],
        "fixed_median_crypto_ms": crypto["fixed_high"]["median_ms"],
        "adaptive_p95_crypto_ms": crypto["adaptive"]["p95_ms"],
        "fixed_p95_crypto_ms": crypto["fixed_high"]["p95_ms"],
        "time_savings_percent": crypto["savings_percent"],
        "mean_paired_difference_ms": paired["mean_difference_ms"],
        "ci95_lower_ms": paired["confidence_interval_95_ms"][0],
        "ci95_upper_ms": paired["confidence_interval_95_ms"][1],
        "adaptive_mean_share_ms": row["share_create"]["adaptive"]["mean_ms"],
        "fixed_mean_share_ms": row["share_create"]["fixed_high"]["mean_ms"],
        "share_savings_percent": row["share_create"]["savings_percent"],
        "adaptive_mean_download_ms": row["download_decrypt"]["adaptive"]["mean_ms"],
        "fixed_mean_download_ms": row["download_decrypt"]["fixed_high"]["mean_ms"],
        "adaptive_mean_local_transfer_ms": row["local_transfer_total"]["adaptive"]["mean_ms"],
        "fixed_mean_local_transfer_ms": row["local_transfer_total"]["fixed_high"]["mean_ms"],
        "adaptive_metadata_bytes": row["metadata_bytes"]["adaptive"],
        "fixed_metadata_bytes": row["metadata_bytes"]["fixed_high"],
        "metadata_savings_percent": row["metadata_bytes"]["savings_percent"],
        "adaptive_kem_ciphertext_bytes": row["kem_ciphertext_bytes"]["adaptive"],
        "fixed_kem_ciphertext_bytes": row["kem_ciphertext_bytes"]["fixed_high"],
        "adaptive_public_key_bytes": row["public_key_bytes"]["adaptive"],
        "fixed_public_key_bytes": row["public_key_bytes"]["fixed_high"],
        "adaptive_total_package_bytes": row["total_package_bytes"]["adaptive"],
        "fixed_total_package_bytes": row["total_package_bytes"]["fixed_high"],
        "adaptive_peak_python_allocation_bytes": row["peak_python_allocation_bytes"]["adaptive"],
        "fixed_peak_python_allocation_bytes": row["peak_python_allocation_bytes"]["fixed_high"],
    }


def export_experiment(run: dict, directory: Path) -> dict[str, Path]:
    if run.get("status") != "COMPLETED":
        raise ValueError("Only complete experiment runs can be exported")
    directory.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": directory / "adaptive_vs_fixed.json",
        "summary_csv": directory / "adaptive_vs_fixed_summary.csv",
        "raw_csv": directory / "adaptive_vs_fixed_raw.csv",
        "aggregate_json": directory / "aggregate.json",
        "summary_text": directory / "summary.txt",
    }
    paths["json"].write_text(json.dumps(run, indent=2) + "\n", encoding="utf-8")
    paths["aggregate_json"].write_text(json.dumps({
        "experiment_run_id": run["experiment_run_id"],
        "scenario_dataset_version": run["scenario_dataset_version"],
        "aggregate": run["aggregate"],
    }, indent=2) + "\n", encoding="utf-8")
    with paths["summary_csv"].open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=SUMMARY_FIELDS)
        writer.writeheader()
        for row in run["comparisons"]:
            writer.writerow(_summary_row(run["experiment_run_id"], row))
    with paths["raw_csv"].open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=RAW_FIELDS)
        writer.writeheader()
        for pair in run["raw_pairs"]:
            for condition in ("adaptive", "fixed_high"):
                sample = pair[condition]
                writer.writerow({
                    "experiment_run_id": run["experiment_run_id"],
                    "scenario_id": pair["scenario_id"], "iteration": pair["iteration"],
                    "execution_order": ">".join(pair["order"]), "condition": condition,
                    "suite_id": sample["suite_id"],
                    "file_size_bytes": sample["file_size_bytes"],
                    "recipient_count": sample["recipient_count"],
                    **{name + "_ms": sample[name + "_ns"] / 1_000_000 for name in (
                        "crypto_total", "local_transfer_total", "share_create",
                        "download_decrypt", "file_encrypt", "file_decrypt",
                        "key_protect", "key_recover")},
                    **{name: sample[name] for name in (
                        "metadata_bytes", "kem_ciphertext_bytes", "public_key_bytes",
                        "total_package_bytes", "peak_python_allocation_bytes")},
                })
    overall = run["aggregate"]["overall"]
    distribution = run["aggregate"]["adaptive_level_distribution"]
    lines = [
        f"Run: {run['experiment_run_id']}",
        f"Scenarios: {overall['scenario_count']}; paired samples: {len(run['raw_pairs'])}",
        "Adaptive level counts: " + ", ".join(
            f"{level}={item['count']}" for level, item in sorted(distribution.items())),
        f"Equal-scenario-weight mean crypto time: adaptive={overall['adaptive_mean_crypto_ms']:.3f} ms, fixed HIGH={overall['fixed_mean_crypto_ms']:.3f} ms",
        f"Time savings (negative means adaptive slower): {overall['time_savings_percent']:.3f}%",
        f"Recipient/file crypto metadata: adaptive={overall['adaptive_metadata_bytes']} B, fixed HIGH={overall['fixed_metadata_bytes']} B",
        f"Metadata savings: {overall['metadata_savings_percent']:.3f}%",
        f"Policy compliance rate: {overall['policy_compliance_rate']:.1%}",
        "These are measured results from this run, not universal performance or security claims.",
    ]
    paths["summary_text"].write_text("\n".join(lines) + "\n", encoding="utf-8")
    return paths
