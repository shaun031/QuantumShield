# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

## Spoken introduction (about 2–4 minutes)

“Classical public-key file-sharing designs may face long-term risks from future quantum computers. QuantumShield is a server-mediated research prototype that combines established components rather than inventing a new cipher. AES-256-GCM encrypts each file once. ML-KEM establishes post-quantum key material for a separately wrapped file key for each recipient; an optional X25519 component creates a hybrid envelope. A deterministic policy selects LOW, STANDARD, or HIGH from explicit labels, while a crypto-suite registry records the exact algorithms and versions. ML-DSA signs file and share packages so tampering is rejected before trusted download. Alice can revoke Bob's *future platform access*, though she cannot erase a copy Bob already saved. Offline benchmarks and a paired Adaptive-versus-Fixed-HIGH experiment measured overhead; 88 controlled security tests probed authentication, authorization, tampering, and failure cleanup. The backend still holds protected private keys and is trusted—this is not zero-knowledge or a production security certification.”

## Preparation

Complete [DEMO_CHECKLIST.md](DEMO_CHECKLIST.md). Start the PostgreSQL service, backend, and frontend with [SETUP.md](SETUP.md). Use two **new synthetic** accounts or known local demo accounts (Alice and Bob) and a harmless small file, such as a locally generated text/PDF fixture. Do not use real personal documents. Record its SHA-256 before the demo:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\path\to\final-demo.pdf'
```

Keep the Phase 13 standard `results.json` and Phase 14 completed `adaptive_vs_fixed.json` under their documented local run directories. The research pages may also import these JSON files through the browser locally; they do not upload them. The demo should never display `.env`, keys, raw JWTs, passwords, or private user files.

The supplied [DEMO_FIXTURE.txt](DEMO_FIXTURE.txt) is a harmless alternative to a PDF. Its verified SHA-256 is recorded in [FINAL_VERIFICATION.md](FINAL_VERIFICATION.md).

## Live sequence

1. Open `/api/health`, `/api/system/status`, and `/docs` on the backend. Explain liveness versus database readiness and show the current OpenAPI contract.
2. Open the React app and log in as Alice. Show Dashboard counts/distributions/recent *supported* audit events and the Security page's five key types, approved suites, provider readiness, and server-managed-key warning.
3. On Upload, choose `AUTO` and `HYBRID` for `final-demo.pdf`; enter explicit `PUBLIC` and `GENERAL` metadata if you want to demonstrate a policy-permitted LOW decision, or a sensitive category such as MEDICAL if you want to demonstrate a HIGH floor. State that the rule is deterministic and does **not** inspect PDF contents. Note the displayed selected level, suite, and reasons.
4. In My Files, show AES-256-GCM, selected hybrid suite, ML-KEM plus X25519, and `VALID` ML-DSA signature. Download as Alice if useful; the file remains one encrypted object on the backend.
5. Share with Bob. Explain that the backend creates Bob's fresh recipient-bound key envelope and SHARE signature; it does not re-encrypt the whole file. Switch to Bob and open Shared With Me. Show `VALID` verification, then download. Compare downloaded SHA-256 with the original using `Get-FileHash`; exact hashes must match.
6. Switch back to Alice, revoke the active Bob share, and show the confirmation text. Switch to Bob and show revoked status/no download button; a direct old share download should return safe 403. Explain prominently that Bob could keep plaintext obtained before revocation. Optionally re-share to illustrate the new grant ID and fresh package.
7. Show the Benchmarks page with the **real** Phase 13 standard export, all six production suites and benchmark-only X25519; explain that timings are synthetic local crypto, not web latency. Show Adaptive Evaluation using the completed Phase 14 standard export and the 24-scenario paired summary. Refer to [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md) for exact provenance and measured values; do not improvise percentages.
8. Open [SECURITY_TESTING.md](SECURITY_TESTING.md). Summarize invalid JWT/IDOR/ciphertext/signature/revocation tests, the two low-severity fixes, and untested production risks. End with the trust model and limitations.

## Failure/fallback plan

- **PQC provider unavailable:** stop the crypto demo, run `backend\.venv\Scripts\python.exe backend\scripts\check_crypto.py` from the project root (or `.\.venv\Scripts\python.exe scripts\check_crypto.py` from `backend`), show the failure honestly, and verify the pinned Windows-compatible Python/wheels. Do not select a weaker fallback.
- **PostgreSQL unavailable:** check service/port/credentials and `DATABASE_URL`; do not reset the database. Use the test/crypto diagnostic and generated report for an offline explanation, clearly saying the live application could not be demonstrated.
- **Benchmark/experiment export absent:** show the UI no-data state, then use an existing validated export or the documented CLI to generate a *new, clearly identified* run. Never present generated example bars as measured results.
- **Frontend port in use:** use a free Vite port and update both `VITE_API_BASE_URL`/backend CORS origin as needed; do not bypass browser security. If a demo account already exists, log in or use a different synthetic email instead of deleting data.
- **Unexpected error:** keep the safe error visible, preserve logs without secrets, and fall back to the verified [project summary](PROJECT_SUMMARY.md) and [results summary](RESULTS_SUMMARY.md). Do not claim a step succeeded when it did not.
