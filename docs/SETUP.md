# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

## Windows-first local setup

This is a server-managed-key research application. Use only development credentials and synthetic/demo files. Do not commit `.env` or submit a real master key. The project directory is `D:\Data Security Project`; commands below assume PowerShell. A recent Python compatible with pinned wheels (the verified run used 3.13.2), Node.js meeting `frontend/package.json` (`>=20.19.0` or `>=22.12.0`), npm, and PostgreSQL are required for a persistent local app. Tests and offline research CLIs have different prerequisites, described below.

For Windows Command Prompt, the local `.env` repair, and database-password troubleshooting, use [WINDOWS_CONFIGURATION.md](WINDOWS_CONFIGURATION.md). Preserve existing `.env` secrets. With dependencies installed, `python scripts\init_dev_env.py` creates a missing local file once with secure keys and refuses to overwrite it.

### 1. PostgreSQL and development secrets

Install/start PostgreSQL and create an empty development database named `quantumshield` using your own administrator account. For example, after connecting with `psql` as an administrator:

```sql
CREATE DATABASE quantumshield;
```

The example configuration uses port **5433 because that port was detected on the original development machine**; use your actual port. Do not reset an existing database merely to demonstrate the project.

```powershell
Set-Location 'D:\Data Security Project\backend'
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
python -c "import secrets; print(secrets.token_urlsafe(64))"
python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Run the generation commands only for a fresh dataset with no existing application secrets; otherwise retain or restore the original keys. Privately put the first generated value in `SECRET_KEY` and the second in `MASTER_KEY_BASE64` inside **untracked** `backend\.env`. Replace the example `DATABASE_URL` password, host, port, and database name with your local PostgreSQL connection. The master key must decode to exactly 32 bytes. Do not regenerate it for an existing database: changing/losing it prevents recovery of protected user private keys and existing files. The demo/dev server uses HTTP; real network deployment requires HTTPS/TLS and an independent security review.

### 2. Backend dependencies and schema

```powershell
Set-Location 'D:\Data Security Project\backend'
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m alembic current
python -m alembic upgrade head
python scripts\check_crypto.py
python -m uvicorn app.main:app --reload
```

If PowerShell script policy blocks activation, use `.\.venv\Scripts\python.exe` explicitly for each Python command; changing system policy is unnecessary. The pinned `cryptography==50.0.2` supplies ML-KEM-768/1024, X25519, AES-GCM and ML-DSA; `mlkem==0.1.0` supplies ML-KEM-512. The original Windows environment installed wheels without a liboqs DLL or compiler. If installation fails, verify Python architecture/version and wheel availability for your environment; do not silently replace crypto packages or use a weaker suite. `check_crypto.py` reports provider and round-trip status without printing keys.

After schema upgrade, existing users created by older phases can receive missing keys without replacing current keys:

```powershell
python scripts\provision_mlkem_keys.py
python scripts\provision_hybrid_keys.py
python scripts\provision_signing_keys.py
```

New registrations already provision the five-key set. The authenticated `POST /api/crypto/keys/ensure` endpoint is another idempotent path. Do not run provisioning against an unknown database or master key.

Check <http://127.0.0.1:8000/api/health> (liveness), <http://127.0.0.1:8000/api/system/status> (database/provider status), and <http://127.0.0.1:8000/docs> (Swagger/OpenAPI). `/api/health` is the actual route, not the historical `/system/health` design sketch.

### 3. Frontend

```powershell
Set-Location 'D:\Data Security Project\frontend'
npm ci
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
npm run lint
npm run build
npm run dev
```

Open <http://localhost:5173>. `VITE_API_BASE_URL` defaults to `http://127.0.0.1:8000/api`; set it to your actual backend URL if changed. Backend `FRONTEND_URL`/`CORS_ORIGINS` must include the exact frontend origin. If Vite selects another port, update both sides rather than assuming CORS will accept it. The project has `lint`, `build`, `dev`, and `preview` npm scripts; no frontend unit-test script is configured.

### 4. Tests and offline research without PostgreSQL

The pytest fixtures supply test-only secrets, an isolated in-memory SQLite schema, and temporary object storage. They must never point at production data. The offline benchmark and adaptive scripts use synthetic data and need installed Python dependencies but no application database or `.env`.

```powershell
Set-Location 'D:\Data Security Project\backend'
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest tests\security -q
.\.venv\Scripts\python.exe scripts\check_final_demo.py
.\.venv\Scripts\python.exe scripts\run_benchmarks.py --profile standard
.\.venv\Scripts\python.exe scripts\run_adaptive_experiment.py --profile standard
.\.venv\Scripts\python.exe scripts\generate_report_summary.py
```

The standard adaptive run requires a complete standard Phase 13 export; the CLI finds the latest or accepts `--phase13-reference`. A quick profile is only a smoke check, not the source of the final measured claims. See [reproducibility](REPRODUCIBILITY.md) before comparing reruns.

### Troubleshooting and custody

If PostgreSQL is unavailable, check its service, port, credentials, and `DATABASE_URL`; `/api/system/status` reports unavailable rather than proving the database is ready. If a PQC provider fails, run `scripts\check_crypto.py` and recheck the pinned wheel environment; never force a weaker fallback. If a user already exists, log in or use distinct synthetic demo accounts; registration is not idempotent. If research exports are absent, the UI must show no-data state—run the CLIs or import a verified export, never substitute invented charts. Keep `backend\benchmark_results` raw JSON/CSV separately if submission requires full auditability; `.gitignore` intentionally excludes those potentially large machine-specific files. Do not include `.env`, private keys, access tokens, or user files in a submission.
