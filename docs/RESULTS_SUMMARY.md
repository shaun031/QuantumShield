# QuantumShield — measured results summary

Generated from existing complete local JSON exports by `backend/scripts/generate_report_summary.py`. This command does not run benchmarks, remeasure data, or substitute sample values. The source exports are ignored by Git and should be retained separately for audit/reproduction.

## Phase 13 benchmark

Source: `backend/benchmark_results/c46c0376-20c0-412b-af4b-7af6ae3dffe6/results.json` (run `c46c0376-20c0-412b-af4b-7af6ae3dffe6`, 2026-10-08T03:34:56.388247+00:00). The tables below are generated from that file.

Profile: `standard`; 5 warmups and 20 measured iterations per operation; clock `time.perf_counter_ns`. Synthetic local pipeline only: no HTTP, authentication, application database, or real user file latency.

Environment: Windows-11-10.0.26200-SP0; CPU `Intel64 Family 6 Model 154 Stepping 4, GenuineIntel`; Python 3.13.2; `cryptography` 50.0.2; `mlkem` 0.1.0. The source records no Git commit.

### ML-KEM primitive measurements

| Parameter set | Keygen mean (ms) | Encapsulate mean (ms) | Decapsulate mean (ms) | Public key (bytes) | KEM ciphertext (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| ML-KEM-512 | 0.030 | 0.029 | 0.065 | 800 | 768 |
| ML-KEM-768 | 0.187 | 0.060 | 0.302 | 1,184 | 1,088 |
| ML-KEM-1024 | 0.299 | 0.102 | 0.293 | 1,568 | 1,568 |

### Recipient-envelope suite measurements

The combined `protect_and_recover` operation is a recipient-envelope crypto measurement, not a full file transfer. `BENCH-X25519-V1` is a benchmark-only classical baseline and is not available for production sharing.

| Suite | Mean (ms) | Median (ms) | P95 (ms) | Metadata (bytes) | Peak Python allocation (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| `BENCH-X25519-V1` | 0.234 | 0.205 | 0.295 | 124 | 778 |
| `QS-PQ-512-V1` | 0.357 | 0.334 | 0.446 | 860 | 3,068 |
| `QS-PQ-768-V1` | 1.063 | 1.039 | 1.153 | 1,180 | 3,398 |
| `QS-PQ-1024-V1` | 1.482 | 1.392 | 1.818 | 1,660 | 3,872 |
| `QS-HYBRID-512-V1` | 1.140 | 1.099 | 1.372 | 892 | 4,979 |
| `QS-HYBRID-768-V1` | 1.848 | 1.804 | 2.012 | 1,212 | 5,314 |
| `QS-HYBRID-1024-V1` | 2.240 | 2.142 | 2.450 | 1,692 | 5,785 |

### AES-256-GCM file-content measurements

| File size (bytes) | Encrypt mean (ms) | Decrypt mean (ms) |
| ---: | ---: | ---: |
| 1,024 | 0.004 | 0.003 |
| 102,400 | 0.027 | 0.025 |
| 1,048,576 | 0.617 | 0.663 |
| 10,485,760 | 5.516 | 6.019 |
| 26,214,400 | 14.466 | 14.103 |

The reported `tracemalloc` value is peak Python allocation during a separate untimed protect operation, not native memory or process RSS. All samples, dispersion, raw nanosecond timings, and additional recipient-count/file-transfer rows remain in the source export.

## Phase 14 adaptive versus Fixed HIGH

Source: `backend/benchmark_results/adaptive/bcec2f67-2984-4e01-8c4d-004ba5c92981/adaptive_vs_fixed.json` (run `bcec2f67-2984-4e01-8c4d-004ba5c92981`, 2026-10-08T14:29:14.910956+00:00). Its Phase 13 reference is `c46c0376-20c0-412b-af4b-7af6ae3dffe6`; reference measurements were not pooled into the paired samples.

Dataset `adaptive-exp-v1`; policy `adaptive-v1`; 24 scenarios × 30 measured pairs per scenario, with alternating execution order. Times are synthetic crypto/local-transfer measurements, not production HTTP/database latency. Savings are `(Fixed HIGH − Adaptive) / Fixed HIGH × 100`; negative values are retained.

| Group | Scenarios | Adaptive mean crypto (ms) | Fixed-HIGH mean crypto (ms) | Time saving | Adaptive metadata (bytes) | Fixed-HIGH metadata (bytes) | Metadata saving |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Overall | 24 | 38.565 | 39.931 | 3.422% | 545,514 | 568,234 | 3.998% |
| PQ_ONLY | 12 | 36.800 | 37.755 | 2.528% | 271,973 | 283,333 | 4.009% |
| HYBRID | 12 | 40.329 | 42.107 | 4.223% | 273,541 | 284,901 | 3.987% |
| Adaptive LOW | 6 | 14.027 | 16.105 | 12.899% | 78,516 | 89,716 | 12.484% |
| Adaptive STANDARD | 6 | 37.839 | 40.299 | 6.105% | 128,046 | 139,566 | 8.254% |
| Adaptive HIGH | 12 | 51.196 | 51.660 | 0.899% | 338,952 | 338,952 | 0.000% |

Adaptive selection distribution: LOW 6 (25.0%), STANDARD 6 (25.0%), HIGH 12 (50.0%).

Policy-compliance rate in this defined scenario set: 100.0%. The HIGH cases use the same suites in both conditions; their small timing difference is noise, not a designed cryptographic advantage. File-size groups are confounded by scenario labels, levels, and recipient counts and are not causal size comparisons.

The source export retains per-scenario raw pairs and descriptive normal-approximation intervals; no formal significance test or universal performance conclusion is claimed.
