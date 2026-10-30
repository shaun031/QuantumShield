# Phase 13: reproducible synthetic benchmarking

## Scope and research questions

The offline CLI measures the six production confidentiality suites and a **benchmark-only** `BENCH-X25519-V1` classical baseline (X25519 + HKDF-SHA256 + AES-256-GCM key wrap). That baseline is not post-quantum resistant and is never registered for normal sharing. The aim is to prepare measured evidence for parameter-size, hybrid overhead, classical-vs-PQ, file-size scaling, and recipient-count questions—not to declare one scheme universally best. Phase 14 uses a separate paired runner and this phase's real standard export as provenance; see [Adaptive evaluation](ADAPTIVE_EVALUATION.md).

The benchmark uses the production `CryptoSuiteRegistry` entries and the actual KEM, X25519, HKDF, AES-GCM, key-wrap, ML-DSA, PQ-share, and hybrid-share providers. It does not alter their production implementations. Synthetic content is generated with `os.urandom`; no user files, identity keys, API sessions, or database records are used.

## Categories and methodology

| Category | What is timed | Exclusions |
| --- | --- | --- |
| `CRYPTO_PRIMITIVE` | ML-KEM keygen/encaps/decaps, X25519 keygen/agreement, HKDF/hybrid HKDF, AES-GCM, key wrap/unwrap, ML-DSA keygen/sign/verify | DB, HTTP, provider setup |
| `CRYPTO_SUITE` | Production recipient-envelope protection, recovery, and their combined time | Recipient key generation, signatures, I/O |
| `FILE_CRYPTO` | In-memory AES-GCM encrypt/decrypt at each file size | KEM, signatures, I/O |
| `SHARE_CRYPTO` | New envelope and ML-DSA signature for each of 1/5/10/25 recipients, according to profile | Validation, DB lookup/write, file re-encryption |
| `END_TO_END` | Synthetic local upload/download pipeline: AES keygen, file encrypt, envelope protect, metadata digest, sign, local write, read, verify, recover, decrypt | HTTP, auth, policy, real application DB |
| `POLICY_SELECTION` / `ADAPTIVE_PREP` | Actual metadata-policy decision and matched adaptive/fixed-HIGH envelope protection for stable synthetic scenarios | Final Phase 14 statistical interpretation |

Every timed operation uses `time.perf_counter_ns()` and runs after warmups. Warmups are excluded. Results retain **all** samples; mean, median, population standard deviation, minimum, maximum, and nearest-rank p95 are calculated in milliseconds. Python GC is left at its default state. Correctness validation is outside primitive and share-creation timing; the synthetic transfer total includes its on-path verification. Every envelope is recovered, every signature verified, and every decrypted file's SHA-256 checked against its original. A failed operation aborts the run rather than exporting apparently valid data.

The `END_TO_END` totals use the complete local pipeline wall-clock window; component rows expose AES, envelope, signature, and local storage costs. Storage writes use the OS page cache and are **not** durable-disk or network latency. The 1/5/10/25-recipient results time new per-recipient envelopes and signatures, never whole-file re-encryption. `tracemalloc` captures peak **Python allocation** for one separate, untimed envelope-protect call; it does not measure native-library allocations or total process RSS.

Public/private key sizes are the actual bytes returned by the selected provider. ML-KEM-512's provider exports an expanded 1,632-byte private key, whereas ML-KEM-768/1024 export 64-byte seeds; these are representation differences, not a direct security-strength ranking. Recipient metadata counts KEM ciphertext, salt, wrapped file key, wrap nonce, and hybrid/classical ephemeral public key. Signature size is separate except in per-recipient aggregate metadata. File package counts ciphertext, nonce, recipient envelope, and signature separately from original plaintext. No application database/JSON serialization overhead or network framing is inferred.

## Profiles, limits, and scenarios

| Profile | Measured iterations | Warmups | File sizes | Recipient counts |
| --- | ---: | ---: | --- | --- |
| `quick` | 3 | 1 | 1 KB, 100 KB, 1 MB | 1, 5 |
| `standard` | 20 | 5 | 1 KB, 100 KB, 1 MB, 10 MB, 25 MB | 1, 5, 10 |
| `full` | 30 | 5 | 1 KB, 100 KB, 1 MB, 10 MB, 25 MB | 1, 5, 10, 25 |

`quick` is a correctness/smoke profile, **not** a publication-grade sample. Command-line overrides are bounded at 100 iterations, 20 warmups, 25 MB per file, 25 recipients, and an 8 GiB per-run content-work budget (sum of sizes × iterations × suites, before reads/writes). Stable policy scenario IDs are `public-general`, `internal-academic`, and `confidential-financial`; the actual `SecurityPolicyEngine` selects their levels. No hardcoded performance direction or fabricated result is used.

## Reproduce on Windows

From `D:\Data Security Project\backend`:

```powershell
python -m venv .venv                         # only if needed
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile quick
.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile standard
.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile quick --file-sizes 1MB,10MB
.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile quick --suite QS-HYBRID-768-V1 --iterations 5 --note "Local validation"
```

No `.env`, PostgreSQL, backend server, or frontend is needed to run the CLI. Each execution writes `benchmark_results/<run_id>/results.json`, `results.csv`, and `samples.csv`; the exact absolute paths are printed. The directory is ignored by Git. `results.json` contains schema version 1, run ID, UTC timestamp, profile, sanitized OS/Python/provider versions, methodology, aggregates, and raw nanosecond samples. `results.csv` has one aggregate row per scenario/operation and includes units in column names. `samples.csv` has raw iteration-level timings. These files contain no keys, shared secrets, or source plaintext. The optional note is truncated to 120 characters; avoid placing identifying information in it.

To view an export, start the frontend and open `/benchmarks` after login. Select `results.json` with the file picker. The page starts empty and never substitutes example measurements; it does not upload the file or permit remote benchmark execution. The view shows suite timing/key sizes, file-size scaling, per-recipient sharing, and synthetic transfer breakdowns with zero-based bars and explicit units.

## Interpreting and limiting results

Capture results on the same machine with minimal background load. OS scheduling, CPU power/thermal state, Python overhead, native-library implementations, and cache effects can influence timings. The environment export identifies platform, Python, `cryptography`, and `mlkem` versions but deliberately omits hostname and personal identifiers. The project directory has no Git metadata, so commit is recorded as unavailable. Results from different runs/machines must not be silently pooled. No sample is dropped as an outlier. An X25519 speed result cannot imply post-quantum protection; hybrid resistance relies on its PQ component under intended assumptions. This server-managed benchmark cannot establish client-side or zero-knowledge performance. Re-run the entire suite if any provider or methodology changes before comparing numbers.
