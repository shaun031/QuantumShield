# Phase 14: Adaptive versus Fixed-HIGH experimental evaluation

## Research question and scientific boundary

**Question:** Can rule-based adaptive selection of post-quantum security configurations reduce computational and communication overhead relative to always selecting the highest supported ML-KEM security level while satisfying QuantumShield's defined application policy?

**Hypothesis (before measurement):** Scenarios permitting LOW or STANDARD may reduce key-establishment and recipient-metadata costs; HIGH scenarios should use the same suite as Fixed HIGH, with only measurement noise in timing. The null hypothesis is no meaningful performance/metadata difference. This is an evaluation of *policy-compliant resource choices*, not a claim that lower ML-KEM levels are equally secure for all content or that Adaptive is intrinsically “more secure.” X25519-only results from Phase 13 are not a condition in this comparison.

## Design and controls

The independent variable is selection strategy: production `SecurityPolicyEngine` AUTO decision versus `FixedHighPolicy` resolving HIGH through the same production `CryptoSuiteRegistry`. The PQ-only track compares adaptive `QS-PQ-{512,768,1024}-V1` to `QS-PQ-1024-V1`; the hybrid track compares adaptive `QS-HYBRID-{512,768,1024}-V1` to `QS-HYBRID-1024-V1`. No adaptive rule, KEM provider, signature profile, or production sharing path is altered for this experiment. The engine's `adaptive-v1` reasons, minimum level, selected level, and exact suite ID are retained. Every scenario verifies selected level ≥ all configured minimums and Fixed HIGH ≥ the same minimum. A mismatch or failed crypto round trip invalidates the run.

Both conditions receive identical deterministic SHAKE-256 synthetic file bytes, file size, labels, category, recipient count, AES file key, ML-DSA-65 signing identity, HKDF-SHA256, AES-256-GCM, software/hardware environment, iterations, and warmups. Synthetic recipient identities and context IDs are paired; each distinct ML-KEM algorithm uses that same user's own correctly typed KEM keypair, generated **outside** timing. In hybrid mode both conditions reuse the same synthetic X25519 identity key. For HIGH scenarios both conditions use the same suite and identity keypair. AES-GCM, KEM, and signature operations use fresh randomized outputs on every trial. The condition order alternates deterministically by scenario index and iteration parity; no uncontrolled shuffle or random-seed claim is made. The original plaintext SHA-256 must equal the decrypted file SHA-256 every time, and every share/file signature and recovered file key is checked.

The Phase 13 `results.json` standard export is a required measured provenance/reference artifact. Its six suite-protect rows, required AES file-size rows, schema, and OS/CPU/Python/library versions are checked before the Phase 14 run. Its numbers are retained separately as context and **never pasted or pooled into Phase 14 paired samples**. The Phase 14 runner reuses the Phase 13 provider facade and `time.perf_counter_ns()` timing method to produce new measurements.

The primary dependent measures are paired mean/median/p95 total crypto time, mean share-creation time, recipient/file crypto-metadata bytes, and signed savings percentages. Secondary measures include file encrypt/decrypt, key protection/recovery, download/decrypt, local-transfer time, KEM ciphertext, public-key bytes, total protected package bytes, and a separately measured peak Python allocation. `crypto_total` is the sum of timed AES, ML-DSA, envelope-protection/recovery, and verification stages. `local_transfer_total` is a wall-clock synthetic local file write/read pipeline. **Neither is a production HTTP/database/authentication/network end-to-end measurement**; OS page caching affects the local I/O track. The experiment does not time revocation.

Savings are `(Fixed HIGH − Adaptive) / Fixed HIGH × 100`; negative values remain negative. Each scenario's N measured iterations form matched pairs. The reported paired difference is Fixed HIGH minus Adaptive in milliseconds; a descriptive 95% interval uses mean ± 1.96 × population SD / √N. This is a normal approximation, **not** a formal significance test or proof of general performance superiority. Mean/median/p95 are retained per condition with no outlier filtering; warmups are excluded. Overall and architecture/level/file-size summaries give *equal weight to each scenario*, rather than pooling large-file or multi-recipient samples with unrelated workloads. The aggregate “p95” field is the mean of scenario p95s, not a pooled p95.

Recipient metadata counts each recipient envelope, each share signature, the file signature, and AES file nonce. `total_package_bytes` also includes ciphertext (with AEAD tag). Public-key bytes reflect provider output representation; ML-KEM-512's expanded private-key form and 768/1024 seed forms are not comparable as security rankings. `tracemalloc` observes only peak Python allocations in a separate untimed recipient-envelope pass, not native crypto memory or process RSS.

## Versioned scenario dataset

Dataset version: `adaptive-exp-v1`. The 12 base scenarios below run in **both** `PQ_ONLY` and `HYBRID`, for 24 standard/full paired scenarios. The quick smoke profile takes public-general, internal-general, and public-medical in both architectures (6 scenarios). The expected level is asserted against the real production policy, not forced into its result.

| Base scenario | Size | Sensitivity / category | Recipients | Expected AUTO level |
| --- | ---: | --- | ---: | --- |
| public-general | 1 KB | PUBLIC / GENERAL | 1 | LOW |
| public-academic | 100 KB | PUBLIC / ACADEMIC | 1 | LOW |
| internal-general | 1 MB | INTERNAL / GENERAL | 1 | STANDARD |
| internal-source-code | 10 MB | INTERNAL / SOURCE_CODE | 1 | STANDARD |
| confidential-financial | 25 MB | CONFIDENTIAL / FINANCIAL | 1 | HIGH |
| confidential-legal | 100 KB | CONFIDENTIAL / LEGAL | 1 | HIGH |
| public-medical | 1 MB | PUBLIC / MEDICAL | 1 | HIGH (category floor) |
| highly-confidential-general | 10 MB | HIGHLY_CONFIDENTIAL / GENERAL | 1 | HIGH |
| public-credentials | 1 KB | PUBLIC / CREDENTIALS | 1 | HIGH (category floor) |
| public-five-recipients | 100 KB | PUBLIC / GENERAL | 5 | LOW |
| internal-ten-recipients | 100 KB | INTERNAL / GENERAL | 10 | STANDARD |
| confidential-twentyfive-recipients | 100 KB | CONFIDENTIAL / GENERAL | 25 | HIGH |

Profiles: `quick` = 5 measured pairs and 1 warmup; `standard` = 30 measured pairs and 5 warmups; `full` = 50 measured pairs and 5 warmups. Iterations/warmups are configurable within 1–100/0–20, with an 8 GiB bounded workload estimate. Quick is only a functional smoke run, not a research conclusion.

## Reproduce and inspect

From `D:\Data Security Project\backend` after installing `requirements.txt`:

```powershell
.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile standard
.\.venv\Scripts\python.exe scripts\run_adaptive_experiment.py --profile quick
.\.venv\Scripts\python.exe scripts\run_adaptive_experiment.py --profile standard
```

The experiment CLI finds the latest Phase 13 standard export by default, or accepts `--phase13-reference path\to\results.json`. It prints the exact absolute paths under `backend\benchmark_results\adaptive\<run_id>\`: `adaptive_vs_fixed.json` (full measured pairs and summaries), `adaptive_vs_fixed_summary.csv` (one flat row per scenario), `adaptive_vs_fixed_raw.csv` (one row per condition/iteration), `aggregate.json`, `summary.txt`, and `status.json`. `status.json` records STARTED, COMPLETED, or FAILED without exporting incomplete comparisons as valid. Runs have unique UUIDs; results are read-only files ignored by Git. Open the frontend `/benchmarks` page after login and import `adaptive_vs_fixed.json` locally; the page does not upload or modify it and has an explicit empty state.

## Limitations and interpretation

The deterministic metadata policy depends on user-provided sensitivity/category. A mislabelled sensitive file can receive a lower configured level because there is no content inspection or ML classifier. Fixed HIGH is simpler and conservative but may incur extra cost where project policy permits LOW/STANDARD. HIGH adaptive and fixed conditions have identical suites, so apparent time differences are noise/order/system effects, not designed security or metadata differences. A single Windows machine, Python overhead, native-library implementation differences (including the ML-KEM-512 provider), OS scheduling, cache state, and thermal changes limit external validity. The CI is approximate; no p-value is computed. Record a new run after any policy/provider/methodology change and never merge pre- and post-change samples.

## Measured results

The following values were generated on this machine on 8 October 2026 from completed runs after the final paired-recipient setup; the JSON/CSV artifacts are the source of truth. Quick run `1a02d5d8-67ef-43ab-80ca-00da55f5d09e` had 6 scenarios × 5 measured pairs, 100% policy compliance, equal-scenario-weight mean crypto time **4.538 ms Adaptive vs 5.270 ms Fixed HIGH** (13.888% measured saving), and **47,276 vs 49,836 metadata bytes** (5.137%). This quick profile is a smoke check only.

Standard run `bcec2f67-2984-4e01-8c4d-004ba5c92981` had **24 scenarios × 30 measured pairs = 720 pairs** (1,440 condition rows), with 5 excluded warmups per scenario, and 100% policy compliance. Adaptive selected LOW in 6, STANDARD in 6, and HIGH in 12 scenarios. Overall equal-scenario-weight mean crypto time was **38.565 ms Adaptive vs 39.931 ms Fixed HIGH**, a **3.422% observed saving**. Total scenario crypto-metadata size was **545,514 vs 568,234 bytes**, a **3.998% saving**. These totals sum one metadata package per scenario rather than multiplying by repeated timing trials.

| Standard-run group | Scenarios | Adaptive mean crypto | Fixed-HIGH mean crypto | Measured time saving | Metadata saving |
| --- | ---: | ---: | ---: | ---: | ---: |
| PQ_ONLY | 12 | 36.800 ms | 37.755 ms | 2.528% | 4.009% |
| HYBRID | 12 | 40.329 ms | 42.107 ms | 4.223% | 3.987% |
| Adaptive LOW | 6 | 14.027 ms | 16.105 ms | 12.899% | 12.484% |
| Adaptive STANDARD | 6 | 37.839 ms | 40.299 ms | 6.105% | 8.254% |
| Adaptive HIGH | 12 | 51.196 ms | 51.660 ms | 0.899% | **0.000%** |

The HIGH rows used identical suites in both conditions. Their small timing difference is measurement/order noise, **not** a designed cryptographic saving. Five of 24 individual scenarios had *negative* measured time savings, including `confidential-legal-pq_only` at −14.46%; these remain in every aggregate. A 25 MB scenario occurred only at HIGH, so file-size-group differences are confounded by the scenario mix and must not be interpreted as a causal size effect. For the 1 KB group the measured time saving was 4.971%, versus 0.724% for the 10 MB group, but those groups have different labels/levels and recipient distributions. The observed metadata saving in the five-recipient LOW PQ case was 14.20%; in the 25-recipient HIGH cases it was zero, as the suites were identical. Per-scenario raw pairs and approximate confidence intervals are retained in the export; no formal significance test was performed.

Machine context: Windows 11, Python 3.13.2, `cryptography` 50.0.2, `mlkem` 0.1.0, Intel64 Family 6 Model 154. Phase 13 reference run: `c46c0376-20c0-412b-af4b-7af6ae3dffe6`. See `backend/benchmark_results/adaptive/<run_id>/` on the machine for full artifacts; those machine-specific outputs are ignored by Git. The results support a modest observed resource saving under **this synthetic scenario distribution and environment**, not an “Adaptive always wins” claim. Misclassification and server-managed-key trust remain material risks.
