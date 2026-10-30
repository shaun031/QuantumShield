"""Framework correctness tests; never assert machine-dependent speed limits."""

import csv
import json

import pytest

from app.benchmarks.config import BASELINE_ID, parse_size
from app.benchmarks.export import export_run
from app.benchmarks.service import BenchmarkService
from app.benchmarks.statistics import summarize


def test_statistics_are_unfiltered_and_nearest_rank_p95() -> None:
    values = [1_000_000, 2_000_000, 3_000_000, 4_000_000, 100_000_000]
    result = summarize(values)
    assert result["sample_count"] == 5
    assert result["median_ms"] == 3
    assert result["min_ms"] == 1
    assert result["max_ms"] == result["p95_ms"] == 100
    assert result["stddev_ms"] > 0
    with pytest.raises(ValueError):
        summarize([])
    with pytest.raises(ValueError):
        summarize([0])


def test_bounded_config_and_unknown_suite_fail() -> None:
    assert parse_size("10MB") == 10 * 1024 * 1024
    with pytest.raises(ValueError):
        parse_size("26MB")
    with pytest.raises(ValueError):
        BenchmarkService(iterations=101, warmups=1, file_sizes=(1024,),
                         recipient_counts=(1,))
    with pytest.raises(ValueError):
        BenchmarkService(iterations=1, warmups=0, file_sizes=(1024,),
                         recipient_counts=(1,), suite_ids=("NOT-A-SUITE",))
    with pytest.raises(ValueError):
        BenchmarkService(iterations=100, warmups=0,
                         file_sizes=(25 * 1024 * 1024,), recipient_counts=(1,))


def test_real_round_trips_export_and_no_secret_fields(tmp_path) -> None:
    service = BenchmarkService(iterations=1, warmups=1, file_sizes=(1024,),
                               recipient_counts=(1,),
                               suite_ids=(BASELINE_ID, "QS-PQ-512-V1", "QS-HYBRID-768-V1"))
    run = service.run(profile="test")
    assert run["benchmark_schema_version"] == 1
    assert run["environment"]["python"]
    assert {BASELINE_ID, "QS-PQ-512-V1", "QS-HYBRID-768-V1"}.issubset(
        {row["suite_id"] for row in run["results"]})
    assert {"CRYPTO_PRIMITIVE", "CRYPTO_SUITE", "FILE_CRYPTO", "SHARE_CRYPTO",
            "END_TO_END", "POLICY_SELECTION", "ADAPTIVE_PREP"}.issubset(
        {row["benchmark_type"] for row in run["results"]})
    assert all(row["sample_count"] == 1 and row["mean_ms"] > 0 and
               row["samples_ns"][0] > 0 for row in run["results"])
    assert all(row["public_key_bytes"] > 0 and row["metadata_overhead_bytes"] > 0
               for row in run["results"] if row["benchmark_type"] == "CRYPTO_SUITE")
    paths = export_run(run, tmp_path / "export")
    loaded = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert loaded["run_id"] == run["run_id"]
    with paths["csv"].open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert len(rows) == len(run["results"])
    assert all(float(row["mean_ms"]) > 0 for row in rows)
    with paths["samples"].open(encoding="utf-8", newline="") as stream:
        samples = list(csv.DictReader(stream))
    assert len(samples) == len(run["results"])
    serialized = paths["json"].read_text(encoding="utf-8")
    assert "private_key\"" not in serialized
    assert "shared_secret\"" not in serialized


def test_file_overhead_and_classical_not_pq(tmp_path) -> None:
    service = BenchmarkService(iterations=1, warmups=0, file_sizes=(1024,),
                               recipient_counts=(1,), suite_ids=(BASELINE_ID,))
    run = service.run(profile="test")
    file_row = next(row for row in run["results"] if row["benchmark_type"] == "FILE_CRYPTO")
    assert file_row["ciphertext_bytes"] == 1024 + 16
    assert file_row["overhead_bytes"] == 28  # 16-byte tag and 12-byte nonce
    baseline = next(row for row in run["results"] if row["suite_id"] == BASELINE_ID)
    assert baseline["post_quantum_resistant"] is False
    assert baseline["kem_ciphertext_bytes"] == 0
