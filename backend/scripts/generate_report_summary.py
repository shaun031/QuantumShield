"""Summarize existing completed research exports without running benchmarks.

Only aggregate measurements and sanitized environment metadata are emitted. The
raw source JSON remains authoritative; missing or incomplete runs become N/A.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any


BACKEND_DIR = Path(__file__).resolve().parents[1]
PROJECT_DIR = BACKEND_DIR.parent
RESULTS_DIR = BACKEND_DIR / "benchmark_results"
DEFAULT_OUTPUT = PROJECT_DIR / "docs" / "RESULTS_SUMMARY.md"
SUITE_IDS = (
    "BENCH-X25519-V1",
    "QS-PQ-512-V1", "QS-PQ-768-V1", "QS-PQ-1024-V1",
    "QS-HYBRID-512-V1", "QS-HYBRID-768-V1", "QS-HYBRID-1024-V1",
)


def read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def complete_benchmark(path: Path) -> dict[str, Any] | None:
    data = read_json(path)
    if not data or data.get("benchmark_schema_version") != 1 or data.get("profile") != "standard":
        return None
    if data.get("run_id") != path.parent.name or not isinstance(data.get("results"), list):
        return None
    rows = data["results"]
    if (not all(isinstance(row, dict) for row in rows)
        or not isinstance(data.get("methodology"), dict)
        or not isinstance(data.get("environment"), dict)
        or not isinstance(data["methodology"].get("file_sizes_bytes"), list)):
        return None
    found = {(row.get("suite_id"), row.get("operation")) for row in rows if isinstance(row, dict)}
    if not all((suite, "protect_and_recover") in found for suite in SUITE_IDS):
        return None
    return data


def complete_adaptive(path: Path) -> dict[str, Any] | None:
    data = read_json(path)
    status = read_json(path.parent / "status.json")
    if (not data or not status or data.get("experiment_schema_version") != 1
        or data.get("experiment_run_id") != path.parent.name
        or data.get("profile") != "standard" or data.get("status") != "COMPLETED"
        or status.get("status") != "COMPLETED"):
        return None
    comparisons = data.get("comparisons")
    if not isinstance(comparisons, list) or len(comparisons) != 24:
        return None
    # Completeness must not select only favorable/compliant research outcomes.
    if not all(isinstance(item, dict) and isinstance(item.get("policy_compliant"), bool)
               for item in comparisons):
        return None
    if (not isinstance(data.get("aggregate"), dict)
        or not isinstance(data.get("methodology"), dict)
        or not isinstance(data.get("phase13_reference"), dict)):
        return None
    aggregate = data["aggregate"]
    for name in ("overall", "by_architecture", "by_adaptive_level", "adaptive_level_distribution"):
        if not isinstance(aggregate.get(name), dict):
            return None
    for name in ("by_architecture", "by_adaptive_level", "adaptive_level_distribution"):
        if not all(isinstance(value, dict) for value in aggregate[name].values()):
            return None
    return data


def latest_complete(folder: Path, filename: str, validator) -> tuple[Path | None, dict[str, Any] | None]:
    candidates = sorted(folder.glob(f"*/{filename}"), key=lambda path: path.stat().st_mtime, reverse=True)
    for path in candidates:
        data = validator(path)
        if data is not None:
            return path, data
    return None, None


def measure(value: Any, digits: int = 3) -> str:
    return (f"{value:,.{digits}f}" if type(value) in (int, float)
            and math.isfinite(value) else "N/A")


def integer(value: Any) -> str:
    return f"{value:,}" if type(value) is int else "N/A"


def row_for(rows: list[dict[str, Any]], **criteria: Any) -> dict[str, Any] | None:
    return next((row for row in rows if all(row.get(key) == value for key, value in criteria.items())), None)


def benchmark_markdown(data: dict[str, Any] | None, path: Path | None) -> list[str]:
    if data is None or path is None:
        return ["## Phase 13 benchmark", "", "N/A — no complete standard benchmark export was found.", ""]
    rows = data["results"]
    method = data.get("methodology", {})
    env = data.get("environment", {})
    out = [
        "## Phase 13 benchmark", "",
        f"Source: `backend/benchmark_results/{data['run_id']}/results.json` (run `{data['run_id']}`, "
        f"{data.get('timestamp', 'timestamp unavailable')}). The tables below are generated from that file.", "",
        f"Profile: `{data.get('profile')}`; {integer(method.get('warmups'))} warmups and "
        f"{integer(method.get('iterations'))} measured iterations per operation; "
        f"clock `{method.get('clock', 'N/A')}`. Synthetic local pipeline only: no HTTP, "
        "authentication, application database, or real user file latency.", "",
        f"Environment: {env.get('os', 'N/A')}; CPU `{env.get('cpu', 'N/A')}`; "
        f"Python {env.get('python', 'N/A')}; `cryptography` {env.get('cryptography', 'N/A')}; "
        f"`mlkem` {env.get('mlkem', 'N/A')}. The source records no Git commit.", "",
        "### ML-KEM primitive measurements", "",
        "| Parameter set | Keygen mean (ms) | Encapsulate mean (ms) | Decapsulate mean (ms) | Public key (bytes) | KEM ciphertext (bytes) |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for algorithm in ("ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"):
        keygen = row_for(rows, benchmark_type="CRYPTO_PRIMITIVE", algorithm=algorithm, operation="keygen") or {}
        encaps = row_for(rows, benchmark_type="CRYPTO_PRIMITIVE", algorithm=algorithm, operation="encapsulate") or {}
        decaps = row_for(rows, benchmark_type="CRYPTO_PRIMITIVE", algorithm=algorithm, operation="decapsulate") or {}
        out.append(f"| {algorithm} | {measure(keygen.get('mean_ms'))} | {measure(encaps.get('mean_ms'))} | "
                   f"{measure(decaps.get('mean_ms'))} | {integer(keygen.get('public_key_bytes'))} | "
                   f"{integer(keygen.get('kem_ciphertext_bytes'))} |")
    out += ["", "### Recipient-envelope suite measurements", "",
            "The combined `protect_and_recover` operation is a recipient-envelope crypto measurement, not a full file transfer. "
            "`BENCH-X25519-V1` is a benchmark-only classical baseline and is not available for production sharing.", "",
            "| Suite | Mean (ms) | Median (ms) | P95 (ms) | Metadata (bytes) | Peak Python allocation (bytes) |",
            "| --- | ---: | ---: | ---: | ---: | ---: |"]
    for suite in SUITE_IDS:
        result = row_for(rows, benchmark_type="CRYPTO_SUITE", suite_id=suite, operation="protect_and_recover") or {}
        out.append(f"| `{suite}` | {measure(result.get('mean_ms'))} | {measure(result.get('median_ms'))} | "
                   f"{measure(result.get('p95_ms'))} | {integer(result.get('metadata_overhead_bytes'))} | "
                   f"{integer(result.get('peak_python_allocation_bytes'))} |")
    out += ["", "### AES-256-GCM file-content measurements", "",
            "| File size (bytes) | Encrypt mean (ms) | Decrypt mean (ms) |",
            "| ---: | ---: | ---: |"]
    for size in method.get("file_sizes_bytes", []):
        encrypt = row_for(rows, benchmark_type="FILE_CRYPTO", file_size_bytes=size, operation="encrypt") or {}
        decrypt = row_for(rows, benchmark_type="FILE_CRYPTO", file_size_bytes=size, operation="decrypt") or {}
        out.append(f"| {integer(size)} | {measure(encrypt.get('mean_ms'))} | {measure(decrypt.get('mean_ms'))} |")
    out += ["", "The reported `tracemalloc` value is peak Python allocation during a separate untimed protect operation, "
            "not native memory or process RSS. All samples, dispersion, raw nanosecond timings, and additional "
            "recipient-count/file-transfer rows remain in the source export.", ""]
    return out


def adaptive_markdown(data: dict[str, Any] | None, path: Path | None) -> list[str]:
    if data is None or path is None:
        return ["## Phase 14 adaptive versus Fixed HIGH", "",
                "N/A — no complete standard adaptive export was found.", ""]
    aggregate = data["aggregate"]
    overall = aggregate.get("overall", {})
    distribution = aggregate.get("adaptive_level_distribution", {})
    method = data.get("methodology", {})
    reference = data.get("phase13_reference", {})
    out = [
        "## Phase 14 adaptive versus Fixed HIGH", "",
        f"Source: `backend/benchmark_results/adaptive/{data['experiment_run_id']}/adaptive_vs_fixed.json` "
        f"(run `{data['experiment_run_id']}`, {data.get('timestamp', 'timestamp unavailable')}). "
        f"Its Phase 13 reference is `{reference.get('run_id', 'N/A')}`; reference measurements were not pooled into the paired samples.", "",
        f"Dataset `{data.get('scenario_dataset_version', 'N/A')}`; policy `{data.get('adaptive_policy_version', 'N/A')}`; "
        f"{integer(overall.get('scenario_count'))} scenarios × {integer(method.get('iterations'))} measured pairs "
        "per scenario, with alternating execution order. Times are synthetic crypto/local-transfer measurements, "
        "not production HTTP/database latency. Savings are `(Fixed HIGH − Adaptive) / Fixed HIGH × 100`; "
        "negative values are retained.", "",
        "| Group | Scenarios | Adaptive mean crypto (ms) | Fixed-HIGH mean crypto (ms) | Time saving | "
        "Adaptive metadata (bytes) | Fixed-HIGH metadata (bytes) | Metadata saving |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    groups = [("Overall", overall)]
    groups += [(name, aggregate.get("by_architecture", {}).get(name, {})) for name in ("PQ_ONLY", "HYBRID")]
    groups += [(f"Adaptive {name}", aggregate.get("by_adaptive_level", {}).get(name, {}))
               for name in ("LOW", "STANDARD", "HIGH")]
    for name, group in groups:
        out.append(f"| {name} | {integer(group.get('scenario_count'))} | "
                   f"{measure(group.get('adaptive_mean_crypto_ms'))} | {measure(group.get('fixed_mean_crypto_ms'))} | "
                   f"{measure(group.get('time_savings_percent'))}% | "
                   f"{integer(group.get('adaptive_metadata_bytes'))} | {integer(group.get('fixed_metadata_bytes'))} | "
                   f"{measure(group.get('metadata_savings_percent'))}% |")
    out += ["", "Adaptive selection distribution: " + ", ".join(
        f"{name} {integer(distribution.get(name, {}).get('count'))} "
        f"({measure(distribution.get(name, {}).get('percent'), 1)}%)"
        for name in ("LOW", "STANDARD", "HIGH")) + ".", "",
        f"Policy-compliance rate in this defined scenario set: "
        f"{measure(overall['policy_compliance_rate'] * 100 if isinstance(overall.get('policy_compliance_rate'), (int, float)) else None, 1)}%. "
        "The HIGH cases use the same suites in both conditions; their small timing difference is noise, "
        "not a designed cryptographic advantage. File-size groups are confounded by scenario labels, levels, "
        "and recipient counts and are not causal size comparisons.", "",
        "The source export retains per-scenario raw pairs and descriptive normal-approximation intervals; "
        "no formal significance test or universal performance conclusion is claimed.", ""]
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark", type=Path, help="Explicit completed standard results.json")
    parser.add_argument("--adaptive", type=Path, help="Explicit completed standard adaptive_vs_fixed.json")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    if args.benchmark:
        benchmark_path, benchmark = args.benchmark.resolve(), complete_benchmark(args.benchmark.resolve())
    else:
        benchmark_path, benchmark = latest_complete(RESULTS_DIR, "results.json", complete_benchmark)
    if args.adaptive:
        adaptive_path, adaptive = args.adaptive.resolve(), complete_adaptive(args.adaptive.resolve())
    else:
        adaptive_path, adaptive = latest_complete(RESULTS_DIR / "adaptive", "adaptive_vs_fixed.json", complete_adaptive)
    lines = ["# QuantumShield — measured results summary", "",
             "Generated from existing complete local JSON exports by `backend/scripts/generate_report_summary.py`. "
             "This command does not run benchmarks, remeasure data, or substitute sample values. "
             "The source exports are ignored by Git and should be retained separately for audit/reproduction.", ""]
    lines += benchmark_markdown(benchmark, benchmark_path)
    lines += adaptive_markdown(adaptive, adaptive_path)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {args.output}")
    print(f"Benchmark source: {benchmark_path if benchmark else 'N/A'}")
    print(f"Adaptive source: {adaptive_path if adaptive else 'N/A'}")


if __name__ == "__main__":
    main()
