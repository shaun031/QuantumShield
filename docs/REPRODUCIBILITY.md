# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

## Evidence and scope

The final report uses only complete existing synthetic exports and test results. The selected Phase 13 standard run is `c46c0376-20c0-412b-af4b-7af6ae3dffe6` (`backend/benchmark_results/<run_id>/results.json`, plus `results.csv` and `samples.csv`). The selected Phase 14 standard run is `bcec2f67-2984-4e01-8c4d-004ba5c92981` (`backend/benchmark_results/adaptive/<run_id>/adaptive_vs_fixed.json`, raw/summary CSV, `aggregate.json`, and `status.json=COMPLETED`). Phase 14's source records the Phase 13 run above as its required reference. The source exports are ignored by Git and must be preserved separately if full raw-data review is required. [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md) is a generated, submission-safe aggregate view, not a replacement for raw exports.

The original standard benchmark used 5 warmups and 20 measured iterations per operation. The standard paired experiment used 24 scenarios × 30 measured pairs, after 5 warmups. The benchmark harness times synthetic local crypto/storage work with `time.perf_counter_ns`, not HTTP, authentication, production PostgreSQL, or network latency. The original machine/provider versions are recorded in the source and generated summary; new runs will differ.

## Reproduce from a clean local Python environment

```powershell
Set-Location 'D:\Data Security Project\backend'
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts\check_crypto.py
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest tests\security -q
.\.venv\Scripts\python.exe scripts\check_final_demo.py
.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile standard
.\.venv\Scripts\python.exe scripts\run_adaptive_experiment.py --profile standard
.\.venv\Scripts\python.exe scripts\generate_report_summary.py
```

Run the adaptive command only after a complete Phase 13 standard export. To bind a specific reference, use `--phase13-reference .\benchmark_results\<run-id>\results.json`. Each CLI creates a new UUID directory; it does **not** overwrite prior measurements. `generate_report_summary.py` reads the latest *complete standard* exports, validates schema/status/scenario presence, and writes `docs/RESULTS_SUMMARY.md`; explicit `--benchmark` and `--adaptive` paths can freeze the selection. Missing/incomplete exports produce `N/A`, never synthetic zeroes or invented figures. To reproduce the published tables precisely, pass the two run paths named above rather than the latest-runs default.

From `D:\Data Security Project\frontend` run `npm ci`, `npm run lint`, and `npm run build`. There is no configured frontend unit-test script. For a persistent application run, configure PostgreSQL and untracked `.env`, run Alembic, and start the backend/frontend as in [SETUP.md](SETUP.md); pytest itself uses isolated SQLite/temp storage and does not require PostgreSQL.

`check_final_demo.py` is a disposable API-level end-to-end rehearsal: it overrides even local environment settings, creates only in-memory SQLite and temporary object storage, registers synthetic Alice/Bob accounts, exercises AUTO/HYBRID upload/signatures/share/download/hash/revocation, and checks dashboard/research reads. It is not a browser, Alembic, or PostgreSQL test.

## Interpretation rules

- Keep the Phase 13 reference measurements separate from new Phase 14 paired samples. Do not pool across machines or changed providers.
- Report the original scenario mix and both architectures; HIGH cases use identical suites in both conditions. Preserve negative savings and all raw samples.
- The Phase 14 descriptive 95% interval is a normal approximation, not a p-value or proof of general superiority.
- Key sizes and metadata bytes are byte counts in the exports. `tracemalloc` peak Python allocation is not total memory use. Local transfer timing is not live HTTP/database latency.
- The Phase 16 suite probes selected attack classes but does not replace independent review or production PostgreSQL concurrency/load testing. See [SECURITY_TESTING.md](SECURITY_TESTING.md).
