# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

## One-minute explanation

QuantumShield is a research-oriented secure file-sharing prototype. It encrypts a file once with AES-256-GCM, then protects access to that file's AES key separately for the owner and each recipient. ML-KEM establishes post-quantum key material; optional X25519 + ML-KEM gives a hybrid migration mode. HKDF-SHA256 derives key-wrapping keys, ML-DSA signs ciphertext/package metadata, and an explainable `adaptive-v1` policy selects LOW/STANDARD/HIGH from user-supplied metadata. Versioned, allow-listed suites prevent silent fallback. Revocation stops *future application downloads*, not copies already obtained.

## Architecture and contribution

React/Vite → FastAPI routes → authentication/authorization → file/share/policy/signature services → crypto-suite providers → PostgreSQL metadata + one local encrypted object. The contribution is **system-level integration and evaluation**, not a novel cipher or an invention of PQC. One ciphertext plus independent recipient envelopes makes multi-recipient sharing possible without re-encrypting the entire file. The backend manages protected private keys and is fully trusted; this is not zero-knowledge.

| Role | Mechanism |
| --- | --- |
| File content | Fresh per-file AES-256-GCM key |
| Post-quantum key establishment | ML-KEM-512/768/1024 |
| Optional hybrid component | Ephemeral X25519 plus ML-KEM |
| Key derivation | HKDF-SHA256 |
| Sender/package authenticity | ML-DSA FILE/SHARE signatures |
| Selection | Deterministic MANUAL/RECOMMEND/AUTO; no machine learning |
| Access | Owner/recipient authorization; ACTIVE→REVOKED share lifecycle |

## Measured result and honest interpretation

The complete standard Phase 14 export (`bcec2f67-2984-4e01-8c4d-004ba5c92981`) has 24 paired scenarios × 30 measured pairs. Adaptive selected LOW in 6, STANDARD in 6, and HIGH in 12, with 100% compliance to the *defined project policy*. Its equal-scenario-weight mean crypto time was **38.565 ms versus 39.931 ms** for Fixed HIGH (**3.422% observed saving**); aggregate metadata was **545,514 versus 568,234 bytes** (**3.998% saving**). These are synthetic, single-machine results, not production request latency or evidence that LOW is suitable for every document. The HIGH cases used identical suites and had zero designed metadata saving. The Phase 13 standard benchmark (`c46c0376-20c0-412b-af4b-7af6ae3dffe6`) measured all six approved suites and benchmark-only X25519. Reproducible tables are in [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md).

The Phase 16 controlled suite passed **88 security cases**; the full backend suite passed **267**. It found and fixed two low-severity error-classification/handling issues without observed plaintext disclosure. Security evidence and untested areas are in [SECURITY_TESTING.md](SECURITY_TESTING.md). Frontend lint and build passed.

## Largest limitations

The backend and application master key can recover user private keys and plaintext. No client-held end-to-end/zero-knowledge guarantee, automatic key rotation, malware/content scanning, formal crypto proof, professional penetration test, or production PostgreSQL concurrency/load assessment exists. User sensitivity labels may be wrong. A recipient can retain a downloaded copy after revocation. ML-KEM-512 uses a beta dependency requiring production review. See the [full report](FINAL_REPORT.md) and [demo script](DEMO_SCRIPT.md).
