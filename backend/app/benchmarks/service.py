"""Offline synthetic measurements using the production cryptographic providers.

No application database, authentication, or user file is accessed here. The
END_TO_END category is a synthetic local-file pipeline, not HTTP latency.
"""

import hashlib
import hmac
import os
import platform
import tempfile
import time
import tracemalloc
from datetime import UTC, datetime
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from uuid import uuid4

from app import __version__
from app.benchmarks.config import BASELINE_ID, MAX_WORKLOAD_BYTES, SCHEMA_VERSION, validate_config
from app.benchmarks.statistics import summarize
from app.crypto.aes import AES256GCMProvider
from app.crypto.hybrid_key_protection import (
    HYBRID_SHARE_AAD_VERSION, HYBRID_SHARE_VERSION, HybridContext, HybridKeyProtector,
    HybridSecretCombiner,
)
from app.crypto.kdf import HKDFSHA256Provider
from app.crypto.kem.factory import build_kem_registry
from app.crypto.key_agreement import X25519Provider
from app.crypto.key_wrap import AESGCMKeyWrapProvider
from app.crypto.security_levels import SecurityLevel
from app.crypto.signatures import MLDSAProvider
from app.crypto.suite_key_protection import SuiteShareKeyContext, SuiteShareKeyProtector
from app.crypto.suite_specs import APPROVED_SUITE_SPECS
from app.crypto.suites import CryptoSuite, CryptoSuiteRegistry, SecurityArchitecture
from app.services.security_policy import (
    DocumentCategory, SecurityAssessmentInput, SecurityPolicyEngine, SelectionMode,
    Sensitivity,
)


_AAD = b"QuantumShield/Benchmark/v1"
_BASE_INFO = b"QuantumShield/Benchmark/X25519/HKDF/v1"


def _package_version(name: str) -> str:
    try:
        return version(name)
    except PackageNotFoundError:
        return "unavailable"


def _now() -> int:
    return time.perf_counter_ns()


class EnvelopeAdapter:
    """Uniform benchmark facade; PQ/hybrid paths call production protectors."""

    def __init__(self, suite_id: str, suites: CryptoSuiteRegistry, agreement: X25519Provider,
                 kdf: HKDFSHA256Provider, wrap: AESGCMKeyWrapProvider) -> None:
        self.suite_id = suite_id
        self.suites = suites
        self.agreement = agreement
        self.kdf = kdf
        self.wrap = wrap
        self.baseline = suite_id == BASELINE_ID
        self.suite = None if self.baseline else suites.get_suite(suite_id, for_encryption=True)
        self.pq_protector = SuiteShareKeyProtector(suites)
        self.hybrid_protector = HybridKeyProtector(suites, agreement)
        self.file_id, self.owner_id, self.recipient_id = uuid4(), uuid4(), uuid4()
        self.share_id, self.kem_key_id, self.classical_key_id = uuid4(), uuid4(), uuid4()

    @property
    def algorithm(self) -> str:
        return "X25519" if self.baseline else self.suite.kem_algorithm

    @property
    def architecture(self) -> str:
        return "CLASSICAL_BASELINE" if self.baseline else self.suite.architecture.value

    @property
    def level(self) -> str:
        return "CLASSICAL" if self.baseline else self.suite.security_level.value

    def recipient(self) -> tuple[object | None, object | None]:
        if self.baseline:
            return None, self.agreement.generate_keypair()
        kem_pair = self.suite.kem.generate_keypair()
        classical = self.agreement.generate_keypair() if self.architecture == "HYBRID" else None
        return kem_pair, classical

    def _context(self, size: int):
        if self.architecture == "PQ_ONLY":
            return SuiteShareKeyContext(
                self.share_id, self.file_id, self.owner_id, self.recipient_id,
                self.kem_key_id, 1, self.suite_id, self.suite.version,
                self.suite.security_level, size,
            )
        return HybridContext(
            purpose="SHARE", file_id=self.file_id, owner_id=self.owner_id,
            recipient_id=self.recipient_id, recipient_kem_key_id=self.kem_key_id,
            recipient_kem_key_version=1, recipient_classical_key_id=self.classical_key_id,
            recipient_classical_key_version=1, suite_id=self.suite_id,
            suite_version=self.suite.version, security_level=self.suite.security_level.value,
            plaintext_size=size, crypto_version=HYBRID_SHARE_VERSION,
            aad_version=HYBRID_SHARE_AAD_VERSION, share_id=self.share_id,
        )

    def protect(self, key: bytes, recipient: tuple[object | None, object | None], size: int):
        kem_pair, classical = recipient
        if self.baseline:
            ephemeral = self.agreement.generate_keypair()
            secret = self.agreement.derive_shared_secret(ephemeral.private_key, classical.public_key)
            salt = os.urandom(self.kdf.salt_size)
            context = _BASE_INFO + self.file_id.bytes + self.recipient_id.bytes + self.share_id.bytes
            kek = self.kdf.derive(secret, salt=salt, info=context)
            wrapped = self.wrap.wrap_key(key, kek, context)
            return {
                "ephemeral": ephemeral.public_key, "salt": salt,
                "wrapped": wrapped.ciphertext, "nonce": wrapped.nonce,
            }
        context = self._context(size)
        if self.architecture == "HYBRID":
            return self.hybrid_protector.protect(key, kem_pair.public_key,
                                                 classical.public_key, context)
        return self.pq_protector.protect(key, kem_pair.public_key, context)

    def recover(self, envelope, recipient: tuple[object | None, object | None], size: int) -> bytes:
        kem_pair, classical = recipient
        if self.baseline:
            secret = self.agreement.derive_shared_secret(classical.private_key, envelope["ephemeral"])
            context = _BASE_INFO + self.file_id.bytes + self.recipient_id.bytes + self.share_id.bytes
            kek = self.kdf.derive(secret, salt=envelope["salt"], info=context)
            return self.wrap.unwrap_key(envelope["wrapped"], kek, envelope["nonce"], context)
        context = self._context(size)
        if self.architecture == "HYBRID":
            return self.hybrid_protector.recover(
                kem_private_key=kem_pair.private_key, classical_private_key=classical.private_key,
                classical_public_key=classical.public_key,
                ephemeral_public_key=envelope.ephemeral_public_key,
                kem_ciphertext=envelope.kem_ciphertext, kdf_salt=envelope.kdf_salt,
                wrapped_file_key=envelope.wrapped_file_key,
                key_wrap_nonce=envelope.key_wrap_nonce, context=context,
            )
        return self.pq_protector.recover(
            recipient_private_key=kem_pair.private_key, kem_ciphertext=envelope.kem_ciphertext,
            kdf_salt=envelope.kdf_salt, wrapped_file_key=envelope.wrapped_file_key,
            key_wrap_nonce=envelope.key_wrap_nonce, kem_algorithm=self.suite.kem_algorithm,
            kdf_algorithm=self.suite.kdf_algorithm,
            key_wrap_algorithm=self.suite.key_wrap_algorithm,
            content_algorithm=self.suite.content_algorithm, context=context,
        )

    def sizes(self, recipient: tuple[object | None, object | None], envelope) -> dict[str, int]:
        kem_pair, classical = recipient
        if self.baseline:
            return {
                "public_key_bytes": len(classical.public_key),
                "private_key_bytes": len(classical.private_key),
                "kem_ciphertext_bytes": 0,
                "ephemeral_public_key_bytes": len(envelope["ephemeral"]),
                "wrapped_key_bytes": len(envelope["wrapped"]),
                "metadata_overhead_bytes": sum(len(envelope[field]) for field in
                                               ("ephemeral", "salt", "wrapped", "nonce")),
            }
        ephemeral = envelope.ephemeral_public_key if self.architecture == "HYBRID" else b""
        return {
            "public_key_bytes": len(kem_pair.public_key) + (len(classical.public_key) if classical else 0),
            "private_key_bytes": len(kem_pair.private_key) + (len(classical.private_key) if classical else 0),
            "kem_ciphertext_bytes": len(envelope.kem_ciphertext),
            "ephemeral_public_key_bytes": len(ephemeral),
            "wrapped_key_bytes": len(envelope.wrapped_file_key),
            "metadata_overhead_bytes": sum(map(len, (
                envelope.kem_ciphertext, envelope.kdf_salt, envelope.wrapped_file_key,
                envelope.key_wrap_nonce, ephemeral,
            ))),
        }


class BenchmarkService:
    """Measure isolated primitives and synthetic secure-transfer workflows."""

    def __init__(self, *, iterations: int, warmups: int, file_sizes: tuple[int, ...],
                 recipient_counts: tuple[int, ...], suite_ids: tuple[str, ...] | None = None) -> None:
        validate_config(iterations, warmups, file_sizes, recipient_counts)
        self.iterations, self.warmups = iterations, warmups
        self.file_sizes, self.recipient_counts = file_sizes, recipient_counts
        self.aead = AES256GCMProvider()
        self.kdf = HKDFSHA256Provider()
        self.wrap = AESGCMKeyWrapProvider(self.aead)
        self.agreement = X25519Provider()
        kem_registry = build_kem_registry()
        self.suites = CryptoSuiteRegistry(tuple(
            CryptoSuite(spec.suite_id, spec.version, SecurityLevel(spec.security_level),
                        self.aead, kem_registry.get(spec.kem), self.kdf, self.wrap,
                        spec.description, architecture=SecurityArchitecture(spec.architecture),
                        classical_algorithm=spec.classical_algorithm)
            for spec in APPROVED_SUITE_SPECS
        ))
        allowed = (BASELINE_ID,) + tuple(spec.suite_id for spec in APPROVED_SUITE_SPECS)
        self.suite_ids = suite_ids or allowed
        if not self.suite_ids or any(item not in allowed for item in self.suite_ids):
            raise ValueError("Unknown benchmark suite")
        if sum(self.file_sizes) * self.iterations * len(self.suite_ids) > MAX_WORKLOAD_BYTES:
            raise ValueError("Benchmark workload exceeds the 8 GiB per-run content budget")
        self.signer = MLDSAProvider("ML-DSA-65")
        self.results: list[dict] = []

    def _record(self, category: str, operation: str, samples: list[int], *,
                suite_id: str = "", algorithm: str = "", architecture: str = "",
                level: str = "", file_size: int = 0, recipient_count: int = 0,
                sizes: dict | None = None, peak_memory: int | None = None,
                scenario: str | None = None) -> None:
        row = {
            "benchmark_type": category, "scenario_id": scenario or
            f"{category.lower()}-{suite_id or algorithm}-{file_size}-{recipient_count}-{operation}".lower(),
            "suite_id": suite_id, "algorithm": algorithm, "architecture": architecture,
            "security_level": level,
            "post_quantum_resistant": (True if architecture in {"PQ_ONLY", "HYBRID"}
                                       or algorithm.startswith("ML-DSA") else
                                       False if architecture == "CLASSICAL_BASELINE" else None),
            "operation": operation, "file_size_bytes": file_size,
            "recipient_count": recipient_count, "warmups": self.warmups,
            "samples_ns": samples, "peak_python_allocation_bytes": peak_memory,
            **summarize(samples), **(sizes or {}),
        }
        self.results.append(row)

    def _single(self, category: str, operation: str, action, validate=lambda _: None, **metadata) -> None:
        for _ in range(self.warmups):
            validate(action())
        samples = []
        for _ in range(self.iterations):
            start = _now()
            outcome = action()
            samples.append(_now() - start)
            validate(outcome)
        self._record(category, operation, samples, **metadata)

    def _primitive_benchmarks(self) -> None:
        for algorithm in build_kem_registry().enabled_algorithms:
            kem = next(suite.kem for suite in self.suites.get_supported_suites()
                       if suite.kem_algorithm == algorithm)
            pair = kem.generate_keypair()
            encapsulated = kem.encapsulate(pair.public_key)
            metadata = {"algorithm": algorithm, "architecture": "PQ_ONLY",
                        "sizes": {"public_key_bytes": len(pair.public_key),
                                  "private_key_bytes": len(pair.private_key),
                                  "kem_ciphertext_bytes": len(encapsulated.ciphertext)}}
            self._single("CRYPTO_PRIMITIVE", "keygen", kem.generate_keypair,
                         lambda value: self._require(len(value.public_key) == kem.public_key_size), **metadata)
            self._single("CRYPTO_PRIMITIVE", "encapsulate",
                         lambda: kem.encapsulate(pair.public_key),
                         lambda value: self._require(len(value.ciphertext) == kem.ciphertext_size), **metadata)
            self._single("CRYPTO_PRIMITIVE", "decapsulate",
                         lambda: kem.decapsulate(pair.private_key, encapsulated.ciphertext),
                         lambda value: self._require(hmac.compare_digest(value, encapsulated.shared_secret)),
                         **metadata)
        left, right = self.agreement.generate_keypair(), self.agreement.generate_keypair()
        expected = self.agreement.derive_shared_secret(left.private_key, right.public_key)
        xmeta = {"algorithm": "X25519", "architecture": "CLASSICAL_BASELINE",
                 "sizes": {"public_key_bytes": 32, "private_key_bytes": 32}}
        self._single("CRYPTO_PRIMITIVE", "keygen", self.agreement.generate_keypair,
                     lambda value: self._require(len(value.public_key) == 32), **xmeta)
        self._single("CRYPTO_PRIMITIVE", "agreement",
                     lambda: self.agreement.derive_shared_secret(right.private_key, left.public_key),
                     lambda value: self._require(hmac.compare_digest(value, expected)), **xmeta)
        self._single("CRYPTO_PRIMITIVE", "hkdf", lambda: self.kdf.derive(
            b"S" * 32, salt=b"A" * 32, info=_AAD),
            lambda value: self._require(len(value) == 32), algorithm="HKDF-SHA256")
        wrapped_key = self.wrap.wrap_key(b"F" * 32, b"K" * 32, _AAD)
        self._single("CRYPTO_PRIMITIVE", "key_wrap", lambda: self.wrap.wrap_key(
            b"F" * 32, b"K" * 32, _AAD),
            lambda value: self._require(len(value.ciphertext) == 48),
            algorithm="KEK-AES-256-GCM")
        self._single("CRYPTO_PRIMITIVE", "key_unwrap", lambda: self.wrap.unwrap_key(
            wrapped_key.ciphertext, b"K" * 32, wrapped_key.nonce, _AAD),
            lambda value: self._require(value == b"F" * 32),
            algorithm="KEK-AES-256-GCM")
        self._single("CRYPTO_PRIMITIVE", "hybrid_hkdf", lambda: HybridSecretCombiner.derive(
            self.kdf, b"P" * 32, b"C" * 32, salt=b"A" * 32, info=_AAD),
            lambda value: self._require(len(value) == 32),
            algorithm="X25519+ML-KEM/HKDF-SHA256", architecture="HYBRID")
        plaintext = os.urandom(1024)
        aes_key = self.aead.generate_key()
        protected = self.aead.encrypt(plaintext, aes_key, _AAD)
        self._single("CRYPTO_PRIMITIVE", "encrypt", lambda: self.aead.encrypt(
            plaintext, aes_key, _AAD), lambda value: self._require(len(value.ciphertext) == 1040),
            algorithm="AES-256-GCM", file_size=1024)
        self._single("CRYPTO_PRIMITIVE", "decrypt", lambda: self.aead.decrypt(
            protected.ciphertext, aes_key, protected.nonce, _AAD),
            lambda value: self._require(hmac.compare_digest(value, plaintext)),
            algorithm="AES-256-GCM", file_size=1024)
        signing_pair = self.signer.generate_keypair()
        message = b"QuantumShield/Benchmark/Signature/v1"
        signature = self.signer.sign(signing_pair.private_key, message)
        sigmeta = {"algorithm": "ML-DSA-65", "sizes": {
            "public_key_bytes": len(signing_pair.public_key),
            "private_key_bytes": len(signing_pair.private_key), "signature_bytes": len(signature)}}
        self._single("CRYPTO_PRIMITIVE", "keygen", self.signer.generate_keypair,
                     lambda value: self._require(len(value.public_key) == self.signer.public_key_size), **sigmeta)
        self._single("CRYPTO_PRIMITIVE", "sign", lambda: self.signer.sign(
            signing_pair.private_key, message),
            lambda value: self._require(self.signer.verify(signing_pair.public_key, message, value)),
            **sigmeta)
        self._single("CRYPTO_PRIMITIVE", "verify", lambda: self.signer.verify(
            signing_pair.public_key, message, signature),
            lambda value: self._require(value), **sigmeta)

    @staticmethod
    def _require(condition: bool) -> None:
        if not condition:
            raise RuntimeError("Benchmark cryptographic round trip failed")

    def _suite_benchmarks(self, adapter: EnvelopeAdapter) -> None:
        recipient = adapter.recipient()
        key = self.aead.generate_key()
        protect_samples, recover_samples = [], []
        for iteration in range(self.warmups + self.iterations):
            start = _now()
            envelope = adapter.protect(key, recipient, 1024)
            protect_ns = _now() - start
            start = _now()
            recovered = adapter.recover(envelope, recipient, 1024)
            recover_ns = _now() - start
            self._require(hmac.compare_digest(key, recovered))
            if iteration >= self.warmups:
                protect_samples.append(protect_ns)
                recover_samples.append(recover_ns)
        tracemalloc.start()
        adapter.protect(key, recipient, 1024)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        sizes = adapter.sizes(recipient, envelope)
        common = dict(suite_id=adapter.suite_id, algorithm=adapter.algorithm,
                      architecture=adapter.architecture, level=adapter.level,
                      file_size=1024, sizes=sizes, peak_memory=peak)
        self._record("CRYPTO_SUITE", "protect", protect_samples, **common)
        self._record("CRYPTO_SUITE", "recover", recover_samples, **common)
        self._record("CRYPTO_SUITE", "protect_and_recover",
                     [a + b for a, b in zip(protect_samples, recover_samples)], **common)

    def _file_benchmarks(self, plaintext: bytes) -> None:
        size = len(plaintext)
        key = self.aead.generate_key()
        expected = hashlib.sha256(plaintext).digest()
        encrypt_samples, decrypt_samples = [], []
        for iteration in range(self.warmups + self.iterations):
            start = _now()
            protected = self.aead.encrypt(plaintext, key, _AAD)
            encrypt_ns = _now() - start
            start = _now()
            recovered = self.aead.decrypt(protected.ciphertext, key, protected.nonce, _AAD)
            decrypt_ns = _now() - start
            self._require(hmac.compare_digest(hashlib.sha256(recovered).digest(), expected))
            if iteration >= self.warmups:
                encrypt_samples.append(encrypt_ns)
                decrypt_samples.append(decrypt_ns)
        overhead = len(protected.ciphertext) + len(protected.nonce) - size
        sizes = {"ciphertext_bytes": len(protected.ciphertext),
                 "metadata_overhead_bytes": len(protected.nonce),
                 "total_package_bytes": len(protected.ciphertext) + len(protected.nonce),
                 "overhead_bytes": overhead, "overhead_percent": overhead / size * 100}
        self._record("FILE_CRYPTO", "encrypt", encrypt_samples,
                     algorithm="AES-256-GCM", file_size=size, sizes=sizes)
        self._record("FILE_CRYPTO", "decrypt", decrypt_samples,
                     algorithm="AES-256-GCM", file_size=size, sizes=sizes)

    def _share_benchmarks(self, adapter: EnvelopeAdapter) -> None:
        signer_pair = self.signer.generate_keypair()
        key = self.aead.generate_key()
        for count in self.recipient_counts:
            recipients = [EnvelopeAdapter(adapter.suite_id, self.suites, self.agreement,
                                          self.kdf, self.wrap) for _ in range(count)]
            recipient_pairs = [item.recipient() for item in recipients]
            samples = []
            last_envelope = None
            for iteration in range(self.warmups + self.iterations):
                start = _now()
                generated = []
                for recipient_adapter, recipient in zip(recipients, recipient_pairs):
                    envelope = recipient_adapter.protect(key, recipient, 1024)
                    message = hashlib.sha256(self._envelope_bytes(recipient_adapter, envelope)).digest()
                    signature = self.signer.sign(signer_pair.private_key, message)
                    last_envelope = envelope
                    generated.append((recipient_adapter, recipient, envelope, message, signature))
                elapsed = _now() - start
                for recipient_adapter, recipient, envelope, message, signature in generated:
                    self._require(self.signer.verify(signer_pair.public_key, message, signature))
                    self._require(hmac.compare_digest(recipient_adapter.recover(envelope, recipient, 1024), key))
                if iteration >= self.warmups:
                    samples.append(elapsed)
            sizes = recipients[-1].sizes(recipient_pairs[-1], last_envelope)
            sizes["signature_bytes"] = len(signature)
            sizes["metadata_overhead_bytes"] = count * (sizes["metadata_overhead_bytes"] + len(signature))
            self._record("SHARE_CRYPTO", "create_shares", samples,
                         suite_id=adapter.suite_id, algorithm=adapter.algorithm,
                         architecture=adapter.architecture, level=adapter.level,
                         file_size=1024, recipient_count=count, sizes=sizes)

    @staticmethod
    def _envelope_bytes(adapter: EnvelopeAdapter, envelope) -> bytes:
        if adapter.baseline:
            return b"".join(envelope[field] for field in ("ephemeral", "salt", "wrapped", "nonce"))
        return b"".join((envelope.kem_ciphertext, envelope.kdf_salt,
                         envelope.wrapped_file_key, envelope.key_wrap_nonce,
                         envelope.ephemeral_public_key if adapter.architecture == "HYBRID" else b""))

    def _transfer_benchmarks(self, adapter: EnvelopeAdapter, plaintext: bytes,
                             directory: Path) -> None:
        size = len(plaintext)
        expected = hashlib.sha256(plaintext).digest()
        recipient = adapter.recipient()
        signing_pair = self.signer.generate_keypair()
        stages = {name: [] for name in (
            "aes_keygen", "file_encrypt", "key_protect", "metadata_prepare", "sign", "storage_write",
            "upload_total", "storage_read", "verify", "key_recover", "file_decrypt",
            "download_total",
        )}
        path = directory / "synthetic-encrypted-file.bin"
        for iteration in range(self.warmups + self.iterations):
            timings = {}
            def stage(name, action):
                start = _now()
                result = action()
                timings[name] = _now() - start
                return result
            upload_start = _now()
            key = stage("aes_keygen", self.aead.generate_key)
            protected = stage("file_encrypt", lambda: self.aead.encrypt(plaintext, key, _AAD))
            envelope = stage("key_protect", lambda: adapter.protect(key, recipient, size))
            message = stage("metadata_prepare", lambda: hashlib.sha256(
                protected.ciphertext + self._envelope_bytes(adapter, envelope)).digest())
            signature = stage("sign", lambda: self.signer.sign(signing_pair.private_key, message))
            stage("storage_write", lambda: path.write_bytes(protected.ciphertext))
            timings["upload_total"] = _now() - upload_start
            download_start = _now()
            on_disk = stage("storage_read", path.read_bytes)
            self._require(on_disk == protected.ciphertext)
            valid = stage("verify", lambda: self.signer.verify(signing_pair.public_key,
                                                               hashlib.sha256(on_disk + self._envelope_bytes(adapter, envelope)).digest(), signature))
            self._require(valid)
            recovered_key = stage("key_recover", lambda: adapter.recover(envelope, recipient, size))
            recovered = stage("file_decrypt", lambda: self.aead.decrypt(on_disk, recovered_key,
                                                                        protected.nonce, _AAD))
            timings["download_total"] = _now() - download_start
            self._require(hmac.compare_digest(hashlib.sha256(recovered).digest(), expected))
            if iteration >= self.warmups:
                for name in stages:
                    stages[name].append(timings[name])
        sizes = adapter.sizes(recipient, envelope)
        sizes["signature_bytes"] = len(signature)
        sizes["ciphertext_bytes"] = len(protected.ciphertext)
        sizes["total_package_bytes"] = (len(protected.ciphertext) + len(protected.nonce)
                                        + sizes["metadata_overhead_bytes"] + len(signature))
        sizes["overhead_bytes"] = sizes["total_package_bytes"] - size
        sizes["overhead_percent"] = sizes["overhead_bytes"] / size * 100
        for name, samples in stages.items():
            self._record("END_TO_END", name, samples, suite_id=adapter.suite_id,
                         algorithm=adapter.algorithm, architecture=adapter.architecture,
                         level=adapter.level, file_size=size, sizes=sizes)

    def _adaptive_scenarios(self) -> None:
        policy = SecurityPolicyEngine()
        scenarios = (
            ("public-general", 100 * 1024, Sensitivity.PUBLIC, DocumentCategory.GENERAL),
            ("internal-academic", 1024 * 1024, Sensitivity.INTERNAL, DocumentCategory.ACADEMIC),
            ("confidential-financial", 10 * 1024 * 1024,
             Sensitivity.CONFIDENTIAL, DocumentCategory.FINANCIAL),
        )
        for name, size, sensitivity, category in scenarios:
            assessment = SecurityAssessmentInput(f"{name}.bin", size,
                                                 "application/octet-stream", sensitivity, category)
            decision = policy.evaluate(assessment, SelectionMode.AUTO)
            samples = []
            for iteration in range(self.warmups + self.iterations):
                start = _now()
                actual = policy.evaluate(assessment, SelectionMode.AUTO)
                elapsed = _now() - start
                self._require(actual.crypto_suite_id == decision.crypto_suite_id)
                if iteration >= self.warmups:
                    samples.append(elapsed)
            self._record("POLICY_SELECTION", "adaptive_decision", samples,
                         suite_id=decision.crypto_suite_id, algorithm=decision.kem_algorithm,
                         architecture="PQ_ONLY", level=decision.selected_level.value,
                         file_size=size, scenario=f"policy-{name}")
            for mode, suite_id in (("adaptive", decision.crypto_suite_id),
                                   ("fixed_high", "QS-PQ-1024-V1")):
                adapter = EnvelopeAdapter(suite_id, self.suites, self.agreement, self.kdf, self.wrap)
                recipient = adapter.recipient()
                key = self.aead.generate_key()
                protected_samples = []
                for iteration in range(self.warmups + self.iterations):
                    start = _now()
                    envelope = adapter.protect(key, recipient, size)
                    elapsed = _now() - start
                    self._require(hmac.compare_digest(adapter.recover(envelope, recipient, size), key))
                    if iteration >= self.warmups:
                        protected_samples.append(elapsed)
                self._record("ADAPTIVE_PREP", f"{mode}_key_protect", protected_samples,
                             suite_id=suite_id, algorithm=adapter.algorithm,
                             architecture=adapter.architecture, level=adapter.level,
                             file_size=size, sizes=adapter.sizes(recipient, envelope),
                             scenario=f"{mode}-{name}")

    def run(self, *, profile: str, note: str = "") -> dict:
        self.results = []
        started = datetime.now(UTC).isoformat()
        self._primitive_benchmarks()
        payloads = {size: os.urandom(size) for size in self.file_sizes}
        for payload in payloads.values():
            self._file_benchmarks(payload)
        with tempfile.TemporaryDirectory(prefix="quantumshield-bench-") as temporary:
            for suite_id in self.suite_ids:
                adapter = EnvelopeAdapter(suite_id, self.suites, self.agreement, self.kdf, self.wrap)
                self._suite_benchmarks(adapter)
                self._share_benchmarks(adapter)
                for payload in payloads.values():
                    self._transfer_benchmarks(adapter, payload, Path(temporary))
        self._adaptive_scenarios()
        return {
            "benchmark_schema_version": SCHEMA_VERSION,
            "run_id": str(uuid4()), "profile": profile, "timestamp": started,
            "note": note[:120],
            "methodology": {
                "clock": "time.perf_counter_ns", "warmups": self.warmups,
                "iterations": self.iterations, "file_sizes_bytes": list(self.file_sizes),
                "recipient_counts": list(self.recipient_counts),
                "gc_policy": "Python default; not disabled", "outlier_policy": "none",
                "memory_metric": "tracemalloc peak Python allocation during one untimed protect operation",
                "scope": "synthetic local pipeline; no HTTP, DB, auth, or real user data",
                "classical_baseline": "X25519 + HKDF-SHA256 + AES-256-GCM key wrap; benchmark only",
            },
            "environment": {
                "os": platform.platform(), "machine": platform.machine(),
                "cpu": platform.processor() or "unavailable", "python": platform.python_version(),
                "cryptography": _package_version("cryptography"),
                "mlkem": _package_version("mlkem"), "quantumshield_version": __version__,
                "commit": "unavailable (no Git metadata in project directory)",
            },
            "results": self.results,
        }
