"""Phase 14 pairing, policy, statistics, and export correctness tests."""

import csv
import json

import pytest

from app.benchmarks.service import BenchmarkService
from app.crypto.suites import SecurityArchitecture
from app.experiments.adaptive import AdaptiveExperimentService, FixedHighPolicy
from app.experiments.analysis import aggregate_results, paired_difference, savings_percent
from app.experiments.export import export_experiment
from app.experiments.scenarios import DATASET_VERSION, load_scenarios
from scripts.run_adaptive_experiment import _write_status
from app.services.security_policy import (
    SecurityAssessmentInput, SecurityPolicyEngine, SelectionMode,
)


def test_versioned_scenarios_exercise_policy_and_both_architectures() -> None:
    assert DATASET_VERSION == "adaptive-exp-v1"
    quick, standard = load_scenarios("quick"), load_scenarios("standard")
    assert len(quick) == 6
    assert len(standard) == 24
    assert {item.architecture for item in standard} == {
        SecurityArchitecture.PQ_ONLY, SecurityArchitecture.HYBRID}
    assert {item.recipient_count for item in standard} == {1, 5, 10, 25}
    assert {item.file_size_bytes for item in standard} == {
        1024, 100 * 1024, 1024 * 1024, 10 * 1024 * 1024, 25 * 1024 * 1024}
    engine = SecurityPolicyEngine()
    for item in standard:
        decision = engine.evaluate(SecurityAssessmentInput(
            f"{item.scenario_id}.bin", item.file_size_bytes, "application/octet-stream",
            item.sensitivity, item.document_category), SelectionMode.AUTO,
            architecture=item.architecture)
        assert decision.selected_level == item.expected_adaptive_level


def test_fixed_high_uses_approved_architecture_mapping() -> None:
    bench = BenchmarkService(iterations=1, warmups=0, file_sizes=(1024,),
                             recipient_counts=(1,))
    policy = FixedHighPolicy(bench.suites)
    assert policy.select(SecurityArchitecture.PQ_ONLY) == "QS-PQ-1024-V1"
    assert policy.select(SecurityArchitecture.HYBRID) == "QS-HYBRID-1024-V1"


def test_paired_recipient_identity_uses_distinct_kem_keys_when_suite_differs() -> None:
    service = AdaptiveExperimentService("quick", iterations=1, warmups=0)
    hybrid_low = next(item for item in service.scenarios if item.architecture is SecurityArchitecture.HYBRID
                      and item.expected_adaptive_level.value == "LOW")
    recipients = service._prepare_recipients(hybrid_low, "QS-HYBRID-512-V1",
                                            "QS-HYBRID-1024-V1")
    adaptive_adapter, adaptive_pair = recipients["adaptive"][0]
    fixed_adapter, fixed_pair = recipients["fixed_high"][0]
    assert adaptive_adapter.recipient_id == fixed_adapter.recipient_id
    assert adaptive_adapter.kem_key_id != fixed_adapter.kem_key_id
    assert adaptive_pair[1] is fixed_pair[1]
    assert adaptive_pair[0] is not fixed_pair[0]


def test_savings_sign_and_paired_difference() -> None:
    assert savings_percent(8, 10) == 20
    assert savings_percent(12, 10) == -20
    assert savings_percent(80, 100) == 20  # byte savings formula
    with pytest.raises(ValueError):
        savings_percent(1, 0)
    paired = paired_difference([8_000_000, 12_000_000], [10_000_000, 10_000_000])
    assert paired["mean_difference_ms"] == 0
    assert paired["median_difference_ms"] == 0
    assert paired["stddev_difference_ms"] == 2
    with pytest.raises(ValueError):
        paired_difference([1], [1, 2])


def test_real_paired_run_and_csv_json_export(tmp_path) -> None:
    phase13 = BenchmarkService(iterations=1, warmups=0,
                               file_sizes=(1024, 1024 * 1024), recipient_counts=(1,)).run(profile="standard")
    service = AdaptiveExperimentService("quick", iterations=1, warmups=0)
    run = service.run(phase13)
    assert run["status"] == "COMPLETED"
    assert run["phase13_reference"]["run_id"] == phase13["run_id"]
    assert len(run["comparisons"]) == 6
    assert len(run["raw_pairs"]) == 6
    assert run["aggregate"]["overall"]["policy_compliance_rate"] == 1
    assert all(run["aggregate"]["adaptive_level_distribution"][level]["count"] == 2
               for level in ("LOW", "STANDARD", "HIGH"))
    assert all(group["scenario_count"] == 3
               for group in run["aggregate"]["by_architecture"].values())
    assert {row["adaptive_level"] for row in run["comparisons"]} == {"LOW", "STANDARD", "HIGH"}
    assert all(row["sample_count"] == 1 and row["crypto_total"]["adaptive"]["mean_ms"] > 0
               for row in run["comparisons"])
    assert all(row["metadata_bytes"]["savings_percent"] == 0 and
               row["adaptive_suite"] == row["fixed_suite"]
               for row in run["comparisons"] if row["adaptive_level"] == "HIGH")
    assert all(row["policy_compliant"] for row in run["comparisons"])
    assert all(pair["adaptive"]["metadata_bytes"] > 0 and
               pair["fixed_high"]["metadata_bytes"] > 0 for pair in run["raw_pairs"])
    paths = export_experiment(run, tmp_path / "experiment")
    restored = json.loads(paths["json"].read_text(encoding="utf-8"))
    assert restored["experiment_run_id"] == run["experiment_run_id"]
    with paths["summary_csv"].open(encoding="utf-8", newline="") as stream:
        summary_rows = list(csv.DictReader(stream))
    with paths["raw_csv"].open(encoding="utf-8", newline="") as stream:
        raw_rows = list(csv.DictReader(stream))
    assert len(summary_rows) == 6
    assert len(raw_rows) == 12
    assert {row["condition"] for row in raw_rows} == {"adaptive", "fixed_high"}
    assert all(float(row["crypto_total_ms"]) > 0 for row in raw_rows)
    assert "private_key\"" not in paths["json"].read_text(encoding="utf-8")


def test_failed_status_is_separate_from_completed_exports(tmp_path) -> None:
    directory = tmp_path / "failed-run"
    _write_status(directory, "test-run", "STARTED")
    assert json.loads((directory / "status.json").read_text())["status"] == "STARTED"
    _write_status(directory, "test-run", "FAILED", "RuntimeError")
    failed = json.loads((directory / "status.json").read_text())
    assert failed["status"] == "FAILED"
    assert failed["error_type"] == "RuntimeError"
    with pytest.raises(ValueError):
        export_experiment({"status": "FAILED"}, directory)


def test_reference_and_aggregate_reject_invalid_inputs() -> None:
    service = AdaptiveExperimentService("quick", iterations=1, warmups=0)
    with pytest.raises(ValueError):
        service.run({"benchmark_schema_version": 1, "run_id": "empty", "results": []})
    with pytest.raises(ValueError):
        aggregate_results([])
    with pytest.raises(ValueError):
        AdaptiveExperimentService("unknown")
