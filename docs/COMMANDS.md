# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

Use PowerShell. These commands match scripts present in the repository. Commands needing PostgreSQL also need a private, correctly configured `backend\.env`; do not point them at production accidentally.

| Task | Command (run from `D:\Data Security Project\backend`) |
| --- | --- |
| Create venv | `python -m venv .venv` |
| Install pinned backend dependencies | `.\.venv\Scripts\python.exe -m pip install -r requirements.txt` |
| Create missing local .env once with secure secrets | `.\.venv\Scripts\python.exe scripts\init_dev_env.py` |
| Check schema version | `.\.venv\Scripts\python.exe -m alembic current` |
| Upgrade schema, never reset | `.\.venv\Scripts\python.exe -m alembic upgrade head` |
| Start backend | `.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload` |
| Full backend tests | `.\.venv\Scripts\python.exe -m pytest -q` |
| Phase 16 security tests | `.\.venv\Scripts\python.exe -m pytest tests\security -q` |
| Crypto diagnostic | `.\.venv\Scripts\python.exe scripts\check_crypto.py` |
| Disposable end-to-end API rehearsal | `.\.venv\Scripts\python.exe scripts\check_final_demo.py` |
| Provision missing ML-KEM keys | `.\.venv\Scripts\python.exe scripts\provision_mlkem_keys.py` |
| Provision missing X25519 keys | `.\.venv\Scripts\python.exe scripts\provision_hybrid_keys.py` |
| Provision missing ML-DSA keys | `.\.venv\Scripts\python.exe scripts\provision_signing_keys.py` |
| Benchmark quick smoke | `.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile quick` |
| Benchmark standard measurement | `.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile standard` |
| Adaptive quick smoke | `.\.venv\Scripts\python.exe scripts\run_adaptive_experiment.py --profile quick` |
| Adaptive standard measurement | `.\.venv\Scripts\python.exe scripts\run_adaptive_experiment.py --profile standard` |
| Regenerate aggregate Markdown from existing exports | `.\.venv\Scripts\python.exe scripts\generate_report_summary.py` |

From `D:\Data Security Project\frontend`:

```powershell
npm ci
npm run lint
npm run build
npm run dev
```

PostgreSQL check: after installing PostgreSQL, use its `pg_isready -h 127.0.0.1 -p <your-port>` utility if available, then verify the app's `/api/system/status`. The example `.env.example` uses 5433 only as a machine-specific starting value. Never put a password directly in this guide or in a committed command line. No `npm test` or remote benchmark-run API exists.
