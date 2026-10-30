# QuantumShield environment configuration on Windows

Commands in this guide use **Windows Command Prompt**, with the project at `D:\Data Security Project`. PowerShell commands remain available in [SETUP.md](SETUP.md).

## Cause and configuration design

The three `Field required` errors occurred because `backend/.env` did not exist and the required `DATABASE_URL`, `SECRET_KEY`, and `MASTER_KEY_BASE64` were not supplied by the process environment. `.env.example` already existed; it is a template and is not loaded automatically as live configuration. `app/core/config.py` already resolves the backend `.env` from the module location using pathlib, so loading is independent of the shell directory. Process environment variables take precedence over the file. Unknown dotenv keys are ignored. Required security settings have no insecure defaults.

Alembic uses that same `Settings.database_url`; there is no second configured connection URL. Its `prepend_sys_path` now resolves relative to `alembic.ini`, permitting commands with an absolute `-c` path from another directory. Settings validation tracebacks hide input values. The existing master-key property rejects malformed Base64 and decoded lengths other than exactly 32 bytes, with a safe error. No key is generated during application startup.

## Create the local configuration once

The local `.env` was created during this repair with secure application secrets. **Do not overwrite it or run secret generation again for existing encrypted data.** On a fresh checkout with no existing `.env` or stored file objects, use:

```bat
cd /d "D:\Data Security Project\backend"
call .venv\Scripts\activate.bat
python scripts\init_dev_env.py
```

The initializer copies `.env.example` and replaces only the JWT/master-key placeholders, using `secrets.token_urlsafe(64)` and Base64 of exactly 32 random bytes. It never displays secret values. Exclusive file creation refuses to overwrite an existing `.env`; existing persistent storage objects also block generation. It does not create a database or weaken PostgreSQL authentication.

If configuring manually on a **fresh** checkout, copy the template only if the local file is absent, generate values once, and enter them privately in `.env`:

```bat
if not exist .env copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(64))"
python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Those manual commands display the new values to you locally. Do not paste them into chat, documentation, source, screenshots, or logs. The actual values created during this repair are not included in this guide.

## Configure PostgreSQL

The detected service is PostgreSQL 18 on `127.0.0.1:5433`. Local IPv4 authentication uses `scram-sha-256`; passwordless access was rejected with `fe_sendauth: no password supplied`. No authentication files were changed. The development target is username `postgres`, database `quantumshield`. Open the local file:

```bat
notepad .env
```

Replace the database password placeholder (`PASSWORD_HERE` in the example, or `CHANGE_ME`) **only in DATABASE_URL** with your actual PostgreSQL password. URL-encode reserved password characters in the SQLAlchemy URL; never disclose the password here. Its expected driver/host/port/database shape is:

```dotenv
DATABASE_URL=postgresql+psycopg://postgres:CHANGE_ME@127.0.0.1:5433/quantumshield
```

The existing Phase 15/17 SQLite databases contain disposable demo data and are separate from this PostgreSQL configuration. Default `storage/files` contained only `.gitkeep` at inspection. During verification, the local environment was edited outside this repair's initializer. Those edits were preserved without displaying credentials. A final read-only connection to the server's `postgres` database succeeded and confirmed that `quantumshield` does not exist. Database creation and migrations were deliberately left pending following the request to leave database setup for now. **If using another database that already has encrypted keys/files from an older setup, restore its original MASTER_KEY_BASE64 before reading or provisioning that data.** A new key cannot recover ciphertext made under an old key. This repair did not reset, drop, create, or migrate any database.

If authenticated PostgreSQL reports that `quantumshield` is absent, create that development database without dropping anything:

```bat
"C:\Program Files\PostgreSQL\18\bin\psql.exe" -h 127.0.0.1 -p 5433 -U postgres -d postgres -W -c "CREATE DATABASE quantumshield;"
```

Run that command only after confirming the database is missing. It prompts for the password rather than embedding one in the command line.

## Required and optional variables

| Variables | Role |
| --- | --- |
| `DATABASE_URL`, `SECRET_KEY`, `MASTER_KEY_BASE64` | Required database URL, JWT signing secret (minimum 32 characters), Base64 master key (32 decoded bytes) |
| `APP_NAME`, `APP_ENV`, `DEBUG`, `API_PREFIX`, `LOG_LEVEL` | Application identity, mode, log verbosity, and API prefix |
| `FRONTEND_URL`, `CORS_ORIGINS` | Exact browser origins; localhost and 127.0.0.1 on port 5173 are allowed |
| `ACCESS_TOKEN_EXPIRE_MINUTES`, `JWT_ALGORITHM` | Access-token lifetime (local template 60 minutes) and HS256 |
| `STORAGE_PATH`, `MAX_UPLOAD_SIZE_MB` | Existing `storage/files` layout and 25 MB limit |
| `DEFAULT_SECURITY_LEVEL`, `DEFAULT_SIGNATURE_ALGORITHM` | STANDARD / ML-DSA-65 defaults |

The template contains all fields from the actual Settings class. Benchmarks use their existing CLI profiles and do not add obsolete environment variables. Root `.gitignore` ignores `.env` and explicitly permits `.env.example`. This directory has no Git metadata, so actual committed-file history could not be checked. Production app configuration contains no embedded JWT/master-key defaults; fixed test values are confined to isolated tests and the disposable API rehearsal.

## Validate and run

After entering the database password locally:

```bat
cd /d "D:\Data Security Project\backend"
call .venv\Scripts\activate.bat
python -c "from app.core.config import settings; print('Config loaded successfully')"
alembic heads
alembic current
alembic upgrade head
alembic current
python -m pytest -q
python scripts\check_crypto.py
uvicorn app.main:app --reload
```

The expected single head is `0011_share_revocation`. Successful `heads` reports migration files; successful `current` confirms the connected database revision. Do not stamp or delete migrations to hide errors.

Check `http://127.0.0.1:8000/api/health`, `/api/system/status`, and `/docs`. Health is liveness; a running server can report a database authentication failure in system status while still being alive.

In a separate Command Prompt:

```bat
cd /d "D:\Data Security Project\frontend"
npm ci
npm run build
npm run dev
```

The frontend already defaults to `VITE_API_BASE_URL=http://127.0.0.1:8000/api` and a 25 MB upload limit. Its `.env.example` exists. No additional frontend `.env` is needed for these defaults. Server secrets, database credentials, and private keys must never be placed in client-visible `VITE_*` variables.

## Verification on 2026-10-10

Configuration imports successfully and the local master key decodes to exactly 32 bytes. Required-field and invalid-key checks remain enabled. The initializer's repeat invocation refuses to replace the existing local file. No generated application secret was found in the checked source, documentation, or example configuration files.

- Backend: 277 tests passed, including configuration regressions and both 30/60-minute token lifetimes. Cryptographic provider, signature, and hybrid round-trip diagnostics passed.
- Backend startup: real `uvicorn app.main:app --reload` startup succeeded; health, OpenAPI, and Swagger returned HTTP 200. System status returned HTTP 503 with `backend=ok` and `database=unavailable`, accurately reflecting the missing target database.
- Alembic: one migration head, `0011_share_revocation`; `current` cannot connect to the missing target database. `upgrade head` was not executed. The absolute `-c` configuration path also resolves the single head from another working directory.
- Frontend: lint and production build passed. The real Vite development server started and its root returned HTTP 200. No frontend environment or source changes were needed.
- The temporary verification servers were stopped after these checks. PostgreSQL authentication settings, existing SQLite demo files, and stored encrypted data were not changed.
