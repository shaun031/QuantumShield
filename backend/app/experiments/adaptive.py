"""Paired Adaptive versus Fixed-HIGH experiment using Phase 13 providers."""

import hashlib
import hmac
import platform
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from uuid import uuid4

from app import __version__
from app.benchmarks.service import BenchmarkService, EnvelopeAdapter
from app.crypto.security_levels import SECURITY_LEVEL_RANK, SecurityLevel
from app.crypto.suites import CryptoSuiteRegistry, SecurityArchitecture
from app.experiments.analysis import aggregate_results, summarize_scenario
from app.experiments.scenarios import DATASET_VERSION, Scenario, load_scenarios
from app.services.security_policy import (
    POLICY_VERSION, SecurityAssessmentInput, SecurityPolicyEngine, SelectionMode,
)


EXPERIMENT_SCHEMA_VERSION = 1
PROFILES = {"quick": (5, 1), "standard": (30, 5), "full": (50, 5)}
_AAD = b"QuantumShield/AdaptiveExperiment/v1"


def _version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _clock() -> int:
    return time.perf_counter_ns()


class FixedHighPolicy:
    """Conservative benchmark condition resolved by the production suite registry."""

    def __init__(self, suites: CryptoSuiteRegistry) -> None:
        self.suites = suites

    def select(self, architecture: SecurityArchitecture) -> str:
        return self.suites.get_suite_for_security_level(SecurityLevel.HIGH,
                                                         architecture).suite_id


class AdaptiveExperimentService:
    def __init__(self, profile: str, *, iterations: int | None = None,
                 warmups: int | None = None) -> None:
        if profile not in PROFILES:
            raise ValueError("Unknown experiment profile")
        default_iterations, default_warmups = PROFILES[profile]
        self.profile = profile
        self.iterations = iterations if iterations is not None else default_iterations
        self.warmups = warmups if warmups is not None else default_warmups
        if not 1 <= self.iterations <= 100 or not 0 <= self.warmups <= 20:
            raise ValueError("Iterations must be 1-100 and warmups 0-20")
        self.scenarios = load_scenarios(profile)
        workload = sum(item.file_size_bytes * item.recipient_count for item in self.scenarios)
        if workload * (self.iterations + self.warmups) > 8 * 1024 * 1024 * 1024:
            raise ValueError("Experiment exceeds the 8 GiB per-run workload budget")
        self.benchmark = BenchmarkService(iterations=1, warmups=0,
                                          file_sizes=(1024,), recipient_counts=(1,))
        self.policy = SecurityPolicyEngine()
        self.fixed_policy = FixedHighPolicy(self.benchmark.suites)
        self.signer = self.benchmark.signer

    def _adapter(self, suite_id: str) -> EnvelopeAdapter:
        bench = self.benchmark
        return EnvelopeAdapter(suite_id, bench.suites, bench.agreement, bench.kdf, bench.wrap)

    @staticmethod
    def _envelope_bytes(adapter: EnvelopeAdapter, envelope) -> bytes:
        return BenchmarkService._envelope_bytes(adapter, envelope)

    def _prepare_recipients(self, scenario: Scenario, adaptive_suite: str,
                            fixed_suite: str) -> dict:
        result = {"adaptive": [], "fixed_high": []}
        for _ in range(scenario.recipient_count):
            adaptive = self._adapter(adaptive_suite)
            fixed = self._adapter(fixed_suite)
            # The synthetic identities and context are paired; only the suite changes.
            for name in ("file_id", "owner_id", "recipient_id", "share_id",
                         "classical_key_id"):
                setattr(fixed, name, getattr(adaptive, name))
            adaptive_pair = adaptive.recipient()
            if adaptive_suite == fixed_suite:
                fixed.kem_key_id = adaptive.kem_key_id
                fixed_pair = adaptive_pair
            else:
                # One synthetic user has distinct KEM keys for distinct algorithms,
                # but a hybrid user retains the same X25519 identity key.
                fixed_pair = (fixed.suite.kem.generate_keypair(), adaptive_pair[1])
            result["adaptive"].append((adaptive, adaptive_pair))
            result["fixed_high"].append((fixed, fixed_pair))
        return result

    def _peak_python_allocation(self, recipients: list, file_key: bytes, size: int) -> int:
        tracemalloc.start()
        try:
            for adapter, pair in recipients:
                adapter.protect(file_key, pair, size)
            _, peak = tracemalloc.get_traced_memory()
            return peak
        finally:
            tracemalloc.stop()

    def _condition(self, *, condition: str, recipients: list, plaintext: bytes,
                   expected_digest: bytes, file_key: bytes, signing_pair,
                   path: Path, memory_peak: int) -> dict:
        aead = self.benchmark.aead
        timings: dict[str, int] = {}

        def stage(name: str, action):
            start = _clock()
            value = action()
            timings[name] = _clock() - start
            return value

        local_start = _clock()
        protected = stage("file_encrypt", lambda: aead.encrypt(plaintext, file_key, _AAD))
        file_message = hashlib.sha256(protected.ciphertext).digest()
        file_signature = stage("file_sign", lambda: self.signer.sign(
            signing_pair.private_key, file_message))
        generated = []
        key_protect_ns = 0
        share_start = _clock()
        for adapter, recipient in recipients:
            start = _clock()
            envelope = adapter.protect(file_key, recipient, len(plaintext))
            key_protect_ns += _clock() - start
            message = hashlib.sha256(file_message + self._envelope_bytes(adapter, envelope)).digest()
            signature = self.signer.sign(signing_pair.private_key, message)
            generated.append((adapter, recipient, envelope, message, signature))
        share_ns = _clock() - share_start
        timings["key_protect"] = key_protect_ns
        timings["share_create"] = share_ns
        stage("storage_write", lambda: path.write_bytes(protected.ciphertext))
        on_disk = stage("storage_read", path.read_bytes)
        if on_disk != protected.ciphertext:
            raise RuntimeError("Synthetic stored ciphertext changed")
        download_start = _clock()
        valid_file = stage("file_verify", lambda: self.signer.verify(
            signing_pair.public_key, hashlib.sha256(on_disk).digest(), file_signature))
        if not valid_file:
            raise RuntimeError("Synthetic file signature verification failed")
        share_verify_ns = 0
        key_recover_ns = 0
        for adapter, recipient, envelope, message, signature in generated:
            start = _clock()
            valid = self.signer.verify(signing_pair.public_key, message, signature)
            share_verify_ns += _clock() - start
            if not valid:
                raise RuntimeError("Synthetic share signature verification failed")
            start = _clock()
            recovered_key = adapter.recover(envelope, recipient, len(plaintext))
            key_recover_ns += _clock() - start
            if not hmac.compare_digest(recovered_key, file_key):
                raise RuntimeError("Synthetic envelope recovery failed")
        recovered = stage("file_decrypt", lambda: aead.decrypt(on_disk, recovered_key,
                                                               protected.nonce, _AAD))
        timings["download_decrypt"] = _clock() - download_start
        if not hmac.compare_digest(hashlib.sha256(recovered).digest(), expected_digest):
            raise RuntimeError("Synthetic file hash verification failed")
        timings["local_transfer_total"] = _clock() - local_start
        timings["share_verify"] = share_verify_ns
        timings["key_recover"] = key_recover_ns
        timings["crypto_total"] = sum(timings[name] for name in (
            "file_encrypt", "file_sign", "share_create", "file_verify",
            "share_verify", "key_recover", "file_decrypt"))
        first_adapter, first_pair, first_envelope, _, _ = generated[0]
        per_recipient = first_adapter.sizes(first_pair, first_envelope)
        sizes = {
            "metadata_bytes": sum(adapter.sizes(pair, envelope)["metadata_overhead_bytes"]
                                  + len(signature) for adapter, pair, envelope, _, signature in generated)
                              + len(file_signature) + len(protected.nonce),
            "kem_ciphertext_bytes": sum(adapter.sizes(pair, envelope)["kem_ciphertext_bytes"]
                                        for adapter, pair, envelope, _, _ in generated),
            "public_key_bytes": sum(adapter.sizes(pair, envelope)["public_key_bytes"]
                                    for adapter, pair, envelope, _, _ in generated),
            "peak_python_allocation_bytes": memory_peak,
        }
        sizes["total_package_bytes"] = len(protected.ciphertext) + sizes["metadata_bytes"]
        return {
            "condition": condition, "suite_id": first_adapter.suite_id,
            "recipient_count": len(generated), "file_size_bytes": len(plaintext),
            "per_recipient_metadata_bytes": per_recipient["metadata_overhead_bytes"] + len(generated[0][4]),
            **{f"{name}_ns": value for name, value in timings.items()}, **sizes,
        }

    @staticmethod
    def _validate_phase13_reference(reference: dict, scenarios: tuple[Scenario, ...],
                                    current_environment: dict) -> dict:
        if reference.get("benchmark_schema_version") != 1 or not reference.get("run_id"):
            raise ValueError("Phase 13 reference must be a completed schema-v1 benchmark export")
        rows = reference.get("results")
        if not isinstance(rows, list):
            raise ValueError("Phase 13 reference has no result rows")
        available = {row.get("suite_id") for row in rows
                     if isinstance(row, dict) and row.get("benchmark_type") == "CRYPTO_SUITE"
                     and row.get("operation") == "protect" and row.get("sample_count", 0) > 0
                     and isinstance(row.get("mean_ms"), (int, float)) and row["mean_ms"] > 0}
        required = {"QS-PQ-512-V1", "QS-PQ-768-V1", "QS-PQ-1024-V1",
                    "QS-HYBRID-512-V1", "QS-HYBRID-768-V1", "QS-HYBRID-1024-V1"}
        if not required.issubset(available):
            raise ValueError("Phase 13 reference must include all six production suites")
        env = reference.get("environment") or {}
        for field in ("os", "machine", "cpu", "python", "cryptography", "mlkem"):
            if env.get(field) != current_environment[field]:
                raise ValueError(f"Phase 13 reference environment mismatch: {field}")
        file_rows = {row.get("file_size_bytes") for row in rows
                     if isinstance(row, dict) and row.get("benchmark_type") == "FILE_CRYPTO"
                     and row.get("operation") == "encrypt" and row.get("sample_count", 0) > 0
                     and isinstance(row.get("mean_ms"), (int, float)) and row["mean_ms"] > 0}
        if not {item.file_size_bytes for item in scenarios}.issubset(file_rows):
            raise ValueError("Phase 13 reference lacks one or more experiment file sizes")
        return {
            "run_id": reference["run_id"], "profile": reference.get("profile"),
            "timestamp": reference.get("timestamp"),
            "schema_version": reference["benchmark_schema_version"],
            "role": "measured method/environment reference; not pooled into Phase 14 paired samples",
            "suite_protect_means_ms": {
                row["suite_id"]: row["mean_ms"] for row in rows
                if isinstance(row, dict) and row.get("benchmark_type") == "CRYPTO_SUITE"
                and row.get("operation") == "protect" and row.get("suite_id") in required
            },
            "aes_encrypt_means_ms_by_file_size": {
                str(row["file_size_bytes"]): row["mean_ms"] for row in rows
                if isinstance(row, dict) and row.get("benchmark_type") == "FILE_CRYPTO"
                and row.get("operation") == "encrypt"
            },
        }

    def run(self, phase13_reference: dict, *, run_id: str | None = None) -> dict:
        run_id = run_id or str(uuid4())
        timestamp = datetime.now(UTC).isoformat()
        environment = {
            "os": platform.platform(), "machine": platform.machine(),
            "cpu": platform.processor() or "unavailable",
            "python": platform.python_version(), "cryptography": _version("cryptography"),
            "mlkem": _version("mlkem"), "quantumshield_version": __version__,
            "commit": "unavailable (no Git metadata in project directory)",
        }
        reference = self._validate_phase13_reference(phase13_reference, self.scenarios,
                                                     environment)
        signing_pair = self.signer.generate_keypair()
        comparisons = []
        raw_pairs = []
        with tempfile.TemporaryDirectory(prefix="quantumshield-adaptive-exp-") as temporary:
            path = Path(temporary) / "synthetic-encrypted-file.bin"
            for scenario_index, scenario in enumerate(self.scenarios):
                assessment = SecurityAssessmentInput(
                    f"{scenario.scenario_id}.bin", scenario.file_size_bytes,
                    "application/octet-stream", scenario.sensitivity,
                    scenario.document_category,
                )
                decision = self.policy.evaluate(assessment, SelectionMode.AUTO,
                                                architecture=scenario.architecture)
                fixed_suite = self.fixed_policy.select(scenario.architecture)
                compliant = (SECURITY_LEVEL_RANK[decision.selected_level] >=
                             SECURITY_LEVEL_RANK[decision.minimum_required_level] and
                             SECURITY_LEVEL_RANK[SecurityLevel.HIGH] >=
                             SECURITY_LEVEL_RANK[decision.minimum_required_level] and
                             decision.selected_level == scenario.expected_adaptive_level and
                             self.benchmark.suites.get_suite(decision.crypto_suite_id).security_level ==
                             decision.selected_level and
                             self.benchmark.suites.get_suite(decision.crypto_suite_id).architecture is
                             scenario.architecture and
                             self.benchmark.suites.get_suite(fixed_suite).security_level is SecurityLevel.HIGH and
                             self.benchmark.suites.get_suite(fixed_suite).architecture is scenario.architecture)
                if not compliant:
                    raise RuntimeError(f"Policy compliance failed for {scenario.scenario_id}")
                recipients = self._prepare_recipients(scenario, decision.crypto_suite_id,
                                                     fixed_suite)
                plaintext = hashlib.shake_256(
                    f"QuantumShield/{DATASET_VERSION}/{scenario.scenario_id}".encode()
                ).digest(scenario.file_size_bytes)
                digest = hashlib.sha256(plaintext).digest()
                shared_key = self.benchmark.aead.generate_key()
                memory = {name: self._peak_python_allocation(items, shared_key,
                                                                scenario.file_size_bytes)
                          for name, items in recipients.items()}
                scenario_pairs = []
                for iteration in range(self.warmups + self.iterations):
                    order = ("adaptive", "fixed_high") if (scenario_index + iteration) % 2 == 0 \
                        else ("fixed_high", "adaptive")
                    outcomes = {}
                    for condition in order:
                        outcomes[condition] = self._condition(
                            condition=condition, recipients=recipients[condition],
                            plaintext=plaintext, expected_digest=digest,
                            file_key=shared_key, signing_pair=signing_pair,
                            path=path, memory_peak=memory[condition],
                        )
                    if iteration >= self.warmups:
                        pair = {
                            "scenario_id": scenario.scenario_id,
                            "iteration": iteration - self.warmups + 1,
                            "order": list(order),
                            "adaptive": outcomes["adaptive"],
                            "fixed_high": outcomes["fixed_high"],
                        }
                        scenario_pairs.append(pair)
                        raw_pairs.append(pair)
                scenario_data = scenario.as_dict()
                scenario_data["adaptive_level"] = decision.selected_level.value
                scenario_data["synthetic_sha256"] = digest.hex()
                summary = summarize_scenario(
                    scenario_data, scenario_pairs, decision.crypto_suite_id,
                    fixed_suite, decision.policy_version, list(decision.reasons), compliant,
                )
                comparisons.append(summary)
        return {
            "experiment_schema_version": EXPERIMENT_SCHEMA_VERSION,
            "experiment_run_id": run_id, "status": "COMPLETED", "timestamp": timestamp,
            "profile": self.profile, "scenario_dataset_version": DATASET_VERSION,
            "adaptive_policy_version": POLICY_VERSION,
            "phase13_reference": reference,
            "environment": environment,
            "methodology": {
                "clock": "time.perf_counter_ns", "iterations": self.iterations,
                "warmups": self.warmups, "order": "alternating by scenario index + iteration parity",
                "content": "deterministic SHAKE-256 synthetic bytes, same within both paired conditions",
                "signing_algorithm": "ML-DSA-65", "file_algorithm": "AES-256-GCM",
                "kdf": "HKDF-SHA256", "gc_policy": "Python default; not disabled",
                "outlier_policy": "none", "scope": "crypto-only and synthetic local transfer; excludes HTTP/auth/DB/network",
                "memory_metric": "untimed tracemalloc peak Python allocation; not process RSS",
                "crypto_total_definition": "sum of timed AES, signatures, share creation, verification, recovery, decryption stages",
                "local_transfer_definition": "wall-clock synthetic local write/read pipeline with crypto and validation",
                "recipient_identity_setup": "outside timed window; same synthetic identity/context per pair",
            },
            "scenarios": [item.as_dict() for item in self.scenarios],
            "comparisons": comparisons, "raw_pairs": raw_pairs,
            "aggregate": aggregate_results(comparisons),
        }
