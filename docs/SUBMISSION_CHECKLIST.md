# QuantumShield submission checklist

Use this for a research-project handoff, not as a claim of production readiness.

## Include

- [ ] Source tree (`backend/app`, `backend/alembic`, `backend/scripts`, `backend/tests`, `frontend/src`) and pinned dependency manifests.
- [ ] Root [README](../README.md), [ROADMAP](../ROADMAP.md), [FINAL_REPORT](FINAL_REPORT.md), [PROJECT_SUMMARY](PROJECT_SUMMARY.md), [SETUP](SETUP.md), [COMMANDS](COMMANDS.md), and [REPRODUCIBILITY](REPRODUCIBILITY.md).
- [ ] [RESULTS_SUMMARY](RESULTS_SUMMARY.md) generated from the named complete Phase 13/14 exports, plus [SECURITY_TESTING](SECURITY_TESTING.md).
- [ ] [DEMO_SCRIPT](DEMO_SCRIPT.md), [DEMO_CHECKLIST](DEMO_CHECKLIST.md), [VIVA_QUESTIONS](VIVA_QUESTIONS.md), and optional unpublished [PAPER_OUTLINE](PAPER_OUTLINE.md).
- [ ] If raw-data audit is required, separately package the exact Phase 13/14 JSON/CSV run directories recorded in [REPRODUCIBILITY](REPRODUCIBILITY.md), after checking that they contain only synthetic inputs and safe machine metadata. They are ignored by Git and will not be included automatically.
- [ ] Record the final test/diagnostic outputs and clearly distinguish the disposable SQLite API/browser checks from an actual PostgreSQL-backed demonstration.
- [ ] Include [FINAL_VERIFICATION.md](FINAL_VERIFICATION.md) and the harmless [DEMO_FIXTURE.txt](DEMO_FIXTURE.txt) if demonstration evidence is requested.

## Exclude or redact

- [ ] No `backend/.env`, master key, passwords, JWTs, protected/private key blobs, user documents, personal data, or application database/storage files.
- [ ] No `.venv`, `node_modules`, `dist`, caches, temporary browser-demo SQLite files, or generated runtime storage.
- [ ] No fabricated figures, stock charts, invented references, or claims that synthetic timing represents live network/HTTP/database latency.

## Before presenting

- [ ] Run the exact commands in [COMMANDS.md](COMMANDS.md) and retain the outputs.
- [ ] Rehearse the full Alice/Bob browser flow in [DEMO_CHECKLIST.md](DEMO_CHECKLIST.md) against the intended local database, including hash match and revoked-download denial.
- [ ] State the trusted-backend/master-key boundary, beta ML-KEM-512 provider, absence of production audit, and inability to retract downloaded plaintext.

The Phase 17 browser smoke test created `backend/phase17_demo.db` and `backend/phase17_demo_storage/` with synthetic accounts only. They are explicitly Git-ignored. Remove them from the final submission package even if local cleanup is blocked.
