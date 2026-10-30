# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

Use this checklist before presenting; do not write secrets or passwords on it.

Phase 17 completed the full Alice/Bob browser flow with the supplied [synthetic fixture](DEMO_FIXTURE.txt) and disposable SQLite on 9 October 2026; see [FINAL_VERIFICATION.md](FINAL_VERIFICATION.md). Re-run the checklist for the intended presentation environment, especially PostgreSQL/Alembic and local secret configuration.

- [ ] PostgreSQL service is running and the *intended development database* is reachable.
- [ ] `backend\.env` exists locally, is not in the submission, and has stable non-placeholder secrets/DB URL.
- [ ] `python -m alembic current` reports the expected head; `upgrade head` is applied only to the intended database.
- [ ] `scripts\check_crypto.py` passes provider, six-suite, signature, and hybrid round trips.
- [ ] Backend `/api/health`, `/api/system/status`, and `/docs` respond appropriately.
- [ ] Frontend `npm run lint` and `npm run build` pass; the browser pages load at the chosen port.
- [ ] Alice and Bob synthetic accounts have required keys; no real user data is used.
- [ ] A small harmless `final-demo.pdf` (or clearly labeled substitute) and its original SHA-256 are ready.
- [ ] AUTO/HYBRID upload, policy decision, signature verification, share, and Bob download work on a rehearsal.
- [ ] Bob's downloaded SHA-256 matches the original; a revoked old grant denies future downloads.
- [ ] Complete Phase 13 standard `results.json` and Phase 14 standard `adaptive_vs_fixed.json` are accessible; charts show actual exports or honest no-data states.
- [ ] [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md), [SECURITY_TESTING.md](SECURITY_TESTING.md), and [DEMO_SCRIPT.md](DEMO_SCRIPT.md) are available as fallback.
- [ ] Backend/frontend ports do not conflict, CORS origin matches, and no browser permission/security warning is bypassed.
- [ ] No `.env`, master key, token, private key, personal file, or production credential will be shown or submitted.
