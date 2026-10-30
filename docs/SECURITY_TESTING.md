# Phase 16 security testing and robustness

## Scope and method

This is a controlled local security regression exercise, **not** a professional penetration test or a formal proof of the cryptographic composition. The dedicated suite is `backend/tests/security/`. It uses an in-memory SQLite test database, a temporary object-storage root, test-only JWT/master keys, generated test-user keys, and FastAPI's in-process test client. No development/production database or real uploaded object is modified. Tests alter only test records and temporary ciphertext. The complete register/login/upload/share/verify/download/tamper/restore/revoke/re-share flow is exercised by `test_complete_local_attack_restore_and_reshare_flow`; this is an API simulation, not a separate browser manual run.

Final local results on 8 October 2026: **88 dedicated Phase 16 security tests passed**, **267 total backend tests passed** (179 pre-Phase-16 baseline plus 88), and frontend `npm run lint` and `npm run build` passed. The source changes were limited to security failure handling, frontend failure messaging, tests, and these security documents; no Phase 17 report was generated.

From `D:\Data Security Project\backend`:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\security -q
.\.venv\Scripts\python.exe -m pytest -q
```

From `D:\Data Security Project\frontend`:

```powershell
npm run lint
npm run build
```

Tests require the pinned native crypto dependencies in `backend/requirements.txt`. They are not silently skipped when a provider is missing: startup/provider checks fail. The `backend/pytest.ini` configuration needs no new marker; the directory command selects the security suite.

## Regression matrix

All cases below passed in the final Phase 16 run unless explicitly marked *review only* or *not tested*. Test names refer to `backend/tests/security/`; earlier functional tests remain in the full suite.

| Attack or failure | Expected control | Security evidence | Result |
| --- | --- | --- | --- |
| Missing, malformed, expired, forged JWT; unknown/inactive account; login enumeration | JWT MAC/claims, active-user lookup, generic login response | `test_auth_authorization.py` bearer/claim/login cases | PASS |
| Cross-user file/share IDOR and unauthorized revoke | Owner/recipient predicates before storage/key access | `test_file_and_share_idor_across_three_users` | PASS |
| Broad search, SQL-like/Unicode text, pagination abuse | Bound/parameterize queries; cap results | search and pagination parameter cases | PASS |
| Traversal, special/XSS-like filenames, duplicate names, orphan object | Generated opaque object key, confined root; React text rendering | `test_upload_storage.py` filename/orphan/duplicate cases; frontend JSX review | PASS; XSS rendering reviewed, not browser-executed |
| Oversized and empty upload; MIME spoofing | 413 with no DB/object; empty file round trip; MIME is advisory | `test_oversize_leaves_no_record_or_object`, `test_empty_and_duplicate_uploads_are_independent`, `test_mime_is_advisory_not_malware_detection` | PASS |
| AES-GCM ciphertext, nonce, wrong key, wrapped key | AEAD verification; no partial plaintext | `test_wrong_aes_key_nonce_and_ciphertext_rejected_without_partial_output`, owner-envelope and replacement cases | PASS |
| Wrong ML-KEM private key, KEM ciphertext/KDF corruption | Exact provider/key context and authenticated unwrap | `test_wrong_mlkem_private_key_and_changed_kdf_context_fail`, recipient-envelope cases | PASS |
| Hybrid single-component failure or package mixing | Both X25519 and ML-KEM required in bound combiner | `test_hybrid_both_components_and_package_binding_required` | PASS |
| Signature byte, signer-key, file/share metadata and ciphertext replacement | Exact signing-key owner/version, canonical payload and ciphertext digest | signature, signed-metadata, package-swap and replacement cases | PASS |
| Unknown/mismatched suite, invalid policy request, unsupported format version | Allow-listed registry, strict policy, no downgrade | suite, adaptive and version cases | PASS |
| Revoked ID/package reuse, re-share, file deletion | State + audit marker before crypto; fresh grant | revocation/deletion/complete-flow cases | PASS |
| Missing ciphertext, signature or crypto row; bad storage key | No plaintext; controlled 404/422; no path traversal | `test_failure_safety.py` missing/corrupt-state cases | PASS |
| Storage write, signing and DB commit failures | Rollback and encrypted-object cleanup | failure-injection cases | PASS |
| Password/private-key storage and secret logging | Argon2id and protected private blobs; redacted logs | `test_password_private_keys_and_file_key_not_persisted_or_logged` | PASS for exercised paths |
| Oversized benchmark/research request or anonymous run | No HTTP benchmark runner; result reads require auth; CLI budgets | protected research route test, code review of bounded CLI | PASS / review only |
| Concurrent duplicate share/revoke/delete races | DB partial unique index and conditional update | existing Phase 12 tests; PostgreSQL locking design | Not stress-tested in Phase 16 |

## Findings and fixes

| Severity | Confirmed issue | Root cause and fix | Verification |
| --- | --- | --- | --- |
| Low | A newly signed/encrypted file whose crypto row vanished returned the *legacy plaintext migration* response (409), misidentifying corruption. No plaintext was exposed. | The missing-metadata branch did not check `signature_required`. It now returns a controlled integrity failure (422) for signed files while retaining the historical unsigned legacy response. | `test_missing_crypto_metadata_is_not_treated_as_legacy`; existing legacy-file test |
| Low | A corrupted internal storage key produced a generic 500 on file download. Root confinement still prevented path escape and plaintext disclosure. | `InvalidStorageKeyError` was not translated at file/share service boundaries. It now yields a controlled 422 for affected download/verify/delete/share paths. | `test_invalid_internal_storage_key_returns_safe_error`, path-confinement cases |
| Informational | Session expiry redirected to login without retaining a clear explanation, and invalid signature badges were terse. | The auth provider now carries session-expiry state to the login route; file/share pages show “This file cannot be trusted” and keep download disabled. | Frontend lint/build and source review; no browser automation in this phase |

No cross-user plaintext disclosure, cryptographic fallback, or secret response was observed in the tested cases. The generic 500 handler continues to hide unexpected internal errors; operational diagnostics remain server-side.

## Security invariants and residual risk

- Persisted passwords are Argon2id hashes. Private key material is encrypted under the configured master key. File AES keys are stored only as authenticated wrapped-key ciphertext; raw KEM secrets and hybrid KEKs have no persistence fields. Python cannot guarantee memory zeroization.
- No unauthorized or revoked application download returned plaintext. Invalid signature and AES-GCM authentication stopped before a plaintext HTTP response. The object store accepts only root-confined internal keys; filenames do not select paths.
- Storage confinement assumes the backend-owned storage tree is not concurrently replaced with hostile symlinks by a local privileged actor; that filesystem race was not tested.
- Server-managed keys mean the backend and master-key authority are trusted. Master-key compromise is serious. Application revocation cannot retract plaintext or key material already copied by a recipient. Database rollback/removal of all revocation markers needs external detection.
- Classification depends on user metadata; no semantic content inspection, malware scan, archive extraction, or zip-bomb scan exists. MIME type is client-provided/advisory. The multipart parser may temporarily spool plaintext outside the encrypted-object directory during upload; request cleanup, host temp-directory controls, and crash recovery need deployment review.
- Rate limiting, quotas beyond upload/query/benchmark bounds, MFA, JWT denylisting, and a full DoS assessment are not implemented. Valid JWTs remain reusable until expiry. PostgreSQL-specific concurrent share/revoke/delete-download races were not load-tested against a real PostgreSQL service; SQLite tests do not prove production lock behavior.
- This was not a dependency vulnerability scan, supply-chain attestation, formal crypto review, external network test, professional pentest, browser XSS execution test, or production TLS/header assessment. Frontend React expressions render the tested filename as text by code inspection. Test-client errors were checked for traceback/SQL/path/secret leakage.

## Configuration and repository review

Backend dependency versions are pinned in `backend/requirements.txt` (including `cryptography==50.0.2`, `mlkem==0.1.0`, `fastapi==0.142.2`, and `PyJWT==2.15.1`); frontend versions are pinned in `frontend/package.json` and `package-lock.json`. No package was upgraded automatically and no live advisory scan was run. The `mlkem` 512 provider is a research/beta dependency requiring independent production review. A source-pattern search found test/config references but no hardcoded production master key or private-key PEM in project source. `backend/.env` was absent. `.gitignore` excludes `.env`, runtime storage, and benchmark exports; the directory has **no Git repository**, so actual tracked-file state could not be verified. Existing ignored Phase 15 local smoke artifacts were left untouched.

Default CORS origins are explicit localhost development origins, with credentials enabled; production must set exact HTTPS origins and serve through TLS. Swagger/OpenAPI remain available for development and may be restricted at deployment. These tests do not establish production readiness.
