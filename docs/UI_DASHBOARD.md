# Phase 15 dashboard and visualization

The authenticated React navigation now separates Dashboard, Upload File, My Files, Shared With Me, Shared By Me, Security, Benchmarks, and Adaptive Evaluation. Existing login, registration, and file-sharing routes remain. No cryptographic provider, policy rule, benchmark method, or database schema was changed.

## Data sources

`GET /api/dashboard/summary` computes owner-scoped file counts, sent/received share counts, active/revoked *sent* share counts, security-level/architecture/selection-mode distributions, active-key readiness, five recent owner-only file decisions, and ten relevant audit events. It uses grouped database queries rather than fetching every file in the browser. `GET /api/dashboard/file-share-counts?file_ids=...` reports active grants only for up to 20 files that the authenticated caller owns. These endpoints never accept a user ID and never return private keys, envelopes, KEM ciphertext, file contents, storage paths, or hashes.

Recent activity is restricted to existing share-created, share-revoked, revoked-download-denied, and file-deleted audit events. Upload/download/verification events are **not** in the current audit schema and are not fabricated. Recipients receive only events relevant to them, with event type/time/role but no other recipient identity. The dashboard's signing-key readiness is not a claim that all signatures verify; individual file/share views call the verification endpoints.

`GET /api/research/benchmarks/latest` and `GET /api/research/adaptive/latest` require authentication and read only fixed filenames in completed local UUID run directories under `backend/benchmark_results`. They return existing synthetic measurements without starting jobs or inventing results. The benchmark endpoint omits the operator-entered `note` field. A missing export returns 404 and the UI shows an explicit empty state. The browser can also import an existing JSON export for local comparison. Research measurements are environment-specific; Phase 13 synthetic transfer omits HTTP/database work, and Phase 14 pairs are crypto/local-transfer measurements, not production request latency.

## Screens

- Dashboard: compact counts, health, key readiness, distributions, relevant audit activity, and recent owner-only policy decisions.
- My Files: paged metadata, within-page search/filters/sort, active-share count, safe security details, signature verification, download/share/delete actions. Delete warns that recipient access ends but existing local copies cannot be erased.
- Shared With Me / Shared By Me: paged status and person filters, safe security details and verification. Revoked downloads are disabled; owner revocation requires confirmation and explains its limit.
- Upload: file, architecture, mode, optional metadata, recommendation/preview, review panel, and success actions. The backend remains authoritative for the final AUTO decision.
- Security: active key metadata and backend-provided approved suites, health/capabilities, plain-language algorithms, and explicit server-managed-key, revocation, and adaptive-classification limitations.
- Benchmarks: latest real Phase 13 export, primitive/suite/AES charts and tables, key/ciphertext/metadata sizes, file and recipient scaling, and no-data/error states.
- Adaptive Evaluation: latest real Phase 14 export, signed savings (including negatives), policy compliance, architecture/level breakdowns, scenario timings, metadata bytes, and file-size analysis.

The charting approach is accessible CSS bars plus data tables; no chart dependency was added. Filters and sorting operate on the current 20-row page, not the entire database. The UI formats byte sizes and local dates while APIs preserve raw values. Browser-client state and presentation never replace backend authorization or cryptographic verification.
