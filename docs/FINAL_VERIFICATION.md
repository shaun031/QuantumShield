# QuantumShield final verification — Phase 17

Recorded on 9 October 2026 (Asia/Calcutta). No research measurements were rerun or altered during final documentation. The published tables were regenerated from the existing complete standard Phase 13/14 exports.

## Automated checks

| Check | Observed result |
| --- | --- |
| `backend/.venv/Scripts/python.exe -m pytest -q` | 267 passed in 54.00 s |
| `backend/.venv/Scripts/python.exe -m pytest tests/security -q` | 88 passed in 19.97 s |
| Frontend `npm run lint` | Exit 0 |
| Frontend `npm run build` | Exit 0; 44 modules transformed |
| `scripts/check_crypto.py` | Provider self-tests, six ACTIVE suites, ML-DSA-65 signature round trip and all three hybrid round trips passed |
| `scripts/check_final_demo.py` | Disposable Alice/Bob AUTO/HYBRID upload/signatures/share/SHA-256/download/dashboard/research/revocation passed |
| Isolated app startup | `/api/health`, `/api/system/status`, `/openapi.json`, `/docs` returned 200 |
| Final documentation links | Relative Markdown file links resolved |
| Report-summary helper | Actual exports accepted; adverse policy outcomes retained; malformed exports rejected; missing/nonfinite values reported N/A |

There is no configured frontend unit-test command. API checks and pytest use isolated SQLite and temporary storage; they do not demonstrate PostgreSQL migrations, production concurrency, or network deployment.

## Full manual browser rehearsal

The localhost Vite/FastAPI application used synthetic Alice/Bob accounts in a separate disposable SQLite database. The browser exercised these steps:

1. Login, registration view, dashboard, Security (five ready keys and six suites), and both standard research views rendered successfully with their actual stored run IDs.
2. Alice selected [DEMO_FIXTURE.txt](DEMO_FIXTURE.txt), AUTO, HYBRID, CONFIDENTIAL sensitivity, and GENERAL category. The preview and upload selected HIGH / `QS-HYBRID-1024-V1` and displayed the policy reasons.
3. My Files displayed the 206-byte file and verified ML-DSA-65 sender signature. Alice found synthetic Bob and created a share.
4. Bob's Shared With Me displayed ACTIVE access, the HIGH hybrid suite, and a verified ML-DSA-65 signature. The browser downloaded `DEMO_FIXTURE.txt`.
5. PowerShell `Get-FileHash -Algorithm SHA256` on source and browser download returned the same hash: `44195948D7A764F06643CEEEF554A7CE5C0C4B1D5C79C9EB13598AB436A9011D`.
6. Alice revoked the share. Bob's view displayed revoked access and a disabled download control. An authenticated direct request for that same grant returned HTTP 403.

The revocation click reported a browser-control timeout, but the subsequent UI showed success and revoked state; Bob's view and the direct HTTP 403 confirmed the resulting state. The backend and frontend demo listeners were no longer running at final handoff. The full PostgreSQL-backed rehearsal still requires local database/secrets configuration: `backend/.env` was absent, and no real database migration was attempted.

## Evidence and local artifacts

Phase 17 created `docs/FINAL_REPORT.md`, `RESULTS_SUMMARY.md`, `SETUP.md`, `COMMANDS.md`, `REPRODUCIBILITY.md`, `PROJECT_SUMMARY.md`, `DEMO_SCRIPT.md`, `DEMO_CHECKLIST.md`, `VIVA_QUESTIONS.md`, `PAPER_OUTLINE.md`, `SUBMISSION_CHECKLIST.md`, `FINAL_VERIFICATION.md`, and `DEMO_FIXTURE.txt`; plus `backend/scripts/generate_report_summary.py` and `backend/scripts/check_final_demo.py`.

It updated root `README.md`, `ROADMAP.md`, `.gitignore`, historical `docs/API_DESIGN.md`, `DATABASE_DESIGN.md`, `ARCHITECTURE.md`, the FastAPI description in `backend/app/main.py`, and login/registration copy in `frontend/src/pages/LoginPage.jsx` and `RegisterPage.jsx`. No cryptographic algorithm, policy rule, or measured source export was changed.

The final research sources are Phase 13 `c46c0376-20c0-412b-af4b-7af6ae3dffe6` and Phase 14 `bcec2f67-2984-4e01-8c4d-004ba5c92981`; [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md) and [REPRODUCIBILITY.md](REPRODUCIBILITY.md) preserve provenance and commands. No benchmark data, percentages, references, or test outcomes were fabricated. Documentation contains configuration names and generation commands, not actual credentials, tokens, master keys, or private keys.

The disposable browser database `backend/phase17_demo.db` and storage `backend/phase17_demo_storage/` remain locally and are explicitly Git-ignored. Automatic command review rejected their deletion with the stated reason `blocked by policy`; no cleanup workaround was used. The harmless downloaded fixture remains at `C:/Users/Shaun/Downloads/DEMO_FIXTURE.txt`. Exclude runtime/demo files from submission using [SUBMISSION_CHECKLIST.md](SUBMISSION_CHECKLIST.md). Existing user data and earlier phase artifacts were left intact.

Phase 17 is complete for the documented research-prototype scope. Residual production controls and future work are listed in [FINAL_REPORT.md](FINAL_REPORT.md) and [SECURITY_TESTING.md](SECURITY_TESTING.md).
