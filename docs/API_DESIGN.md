# REST API Design

## Current implementation note (Phase 17)

The sections below include early phase design sketches and snapshots. The running FastAPI OpenAPI document at `/docs` or `/openapi.json`, `backend/app/api/routes/`, and tests are authoritative for the **current** contract. The actual API prefix is `/api`. Liveness is `GET /api/health`; provider/database status is `GET /api/system/status`. File and sent/received share lists use bounded `limit`/`offset` query parameters, **not cursor pagination**. Normal FastAPI errors use `{"detail": ...}` (and validation uses its usual detail list), **not** the nested `error.code/message/correlation_id` shape proposed later in this document. There is no general request correlation ID or built-in production rate limiter; these remain hardening work. Research result routes are authenticated, read-only `GET /api/research/benchmarks/latest` and `GET /api/research/adaptive/latest`; they read local exports rather than starting measurements.

See [FINAL_REPORT.md](FINAL_REPORT.md) for the final architecture and [SETUP.md](SETUP.md) for verified URLs. Historical sections below should not be treated as endpoint guarantees.

## Phase 12 share lifecycle API

Owner-only `POST /api/shares/{share_id}/revoke` accepts optional `reason` (maximum 255 characters) and returns the current revoked share on retry. Sender/recipient share list and detail responses include status and revoked timestamp, including historical revoked rows. Recipient download returns safe 403 for a revoked grant before cryptographic work; unrelated or unauthorized callers still receive 404. Re-sharing uses the existing create endpoint but creates a new ID/envelope/signature when only revoked history exists. See [Access revocation](ACCESS_REVOCATION.md).

## Phase 11 authenticity API

`GET /api/files/{id}/verify` is owner-only; `GET /api/shares/{id}/verify` is visible only to the sender/recipient. They return `VALID`, `INVALID`, or `LEGACY_UNSIGNED` plus safe algorithm/profile/signer ID for a valid signature. File/share metadata includes `signature_required`; key metadata includes `key_purpose`, and authenticated `GET /api/crypto/signing-key/{user_id}` exposes only the active signing public key. New uploads and shares are server-signed; neither accepts arbitrary signing algorithms. Owner and recipient downloads independently verify current ciphertext and signatures before decryption and return safe `422` on invalid signatures. `POST /api/crypto/keys/ensure` now provisions five keys, including ML-DSA-65. See [Digital signatures](DIGITAL_SIGNATURES.md).

## Phase 10 API additions

`POST /api/files/upload` accepts `security_architecture=PQ_ONLY|HYBRID` (default `PQ_ONLY`) alongside the existing level/mode. `POST /api/security/recommend` accepts the same architecture for a suite-aware preview, but the underlying adaptive policy still selects only a level. Options expose the two architectures; suite discovery lists six suites with `architecture` and `classical_algorithm`. File/share responses expose the selected architecture and classical algorithm, never private keys or shared secrets. `GET /api/crypto/keys/me` and the exact public-key lookup include X25519; Phase 11 expands the keyset to five with ML-DSA-65. Missing hybrid recipient keys return a safe conflict, and authenticated envelope failure returns safe `422` without plaintext. See [Hybrid cryptography](HYBRID_CRYPTO.md). Historical endpoint descriptions below remain for their respective phases.

## Phase 9 capability discovery

Authenticated `GET /api/crypto/suites` returns allow-listed suite IDs, version, lifecycle status, security level, provider identifiers, description, and availability—never key material. Security options and decisions include `suite_id`/`crypto_suite_id`; file and share responses include stored suite metadata. `/api/system/status` reports safe provider identifiers, supported suites, and active suite count.

## 1. Historical design conventions (not all implemented)

- Current implementation base path through Phase 8: `/api`. A future versioned prefix requires an explicit compatibility plan.
- JSON uses UTF-8 except `multipart/form-data` upload and streamed download.
- Resource IDs are UUIDs. They reduce accidental enumeration but never replace authorization.
- Access tokens are sent as `Authorization: Bearer <token>`. The Phase 2 browser client keeps the token in `sessionStorage`; see the security model for limitations.
- Timestamps are ISO 8601 UTC. Pagination uses a documented cursor and bounded `limit`.
- Mutations accept/return a correlation/request ID; sensitive endpoints are rate-limited.
- Algorithm choices sent by a client are requests/preferences only. Server policy returns the effective selection.
- Responses never expose password hashes, private keys, AES keys, shared secrets, derived KEKs, internal storage paths/object keys, or secret configuration.

## 2. Historical proposed error shape (not implemented)

```json
{
  "error": {
    "code": "FILE_NOT_ACCESSIBLE",
    "message": "The file is unavailable or you are not permitted to access it.",
    "correlation_id": "uuid"
  }
}
```

Use stable codes and safe messages. Validation errors identify safe fields. Cryptographic failures should not reveal whether a private key, KEM ciphertext, wrapped key, tag, or AAD was the failing oracle. For protected resources, prefer a common `404`/safe response where distinguishing existence would leak information.

## 3. Authentication and users

### `POST /api/auth/register` (**implemented through Phase 7**)

- **Purpose:** create a normal user account.
- **Authentication:** none. Rate limiting/abuse controls are required before public deployment but are not implemented in Phase 2.
- **Body:** `{ "name": "...", "email": "...", "password": "..." }`.
- **Response:** `201` with safe user profile; no password/token unless the product explicitly chooses auto-login later.
- **Rules:** normalize email, hash with Argon2id, and transactionally create one protected key version for each of `ML-KEM-512`, `ML-KEM-768`, and `ML-KEM-1024`. Any key-provisioning failure rolls back registration.

### `POST /api/auth/login` (**implemented in Phase 2**)

- **Purpose:** verify credentials and issue a short-lived access token.
- **Authentication:** none; invalid, unknown, and inactive accounts receive the same `401` response. Rate limiting is still required.
- **Body:** `{ "email": "...", "password": "..." }`.
- **Response:** `{ "access_token": "...", "token_type": "bearer", "expires_in": 1800 }` by default.
- **Rules:** active accounts only; verify with `pwdlib`; create an HS256 JWT containing only required `sub`, `iat`, `exp`, and `type=access` claims; never log passwords or raw tokens.

### `POST /api/auth/refresh` and `POST /api/auth/logout` (not implemented)

- **Purpose:** rotate a refresh session; revoke/logout respectively.
- **Authentication:** valid refresh/session credential under the chosen model.
- **Body/response:** transport-specific token/session data; never persist raw refresh tokens server-side.
- **Rules:** any future refresh-token design must define rotation, reuse detection, bounded lifetime, and server-side revocation. Current logout only removes the browser token.

### `GET /api/users/me` (**implemented in Phase 2**)

- **Purpose:** return the current safe user profile.
- **Authentication:** required.
- **Response:** `{ "id", "name", "email", "is_active", "created_at", "updated_at" }`.
- **Rules:** resolve the actor only from the validated bearer token; require an existing active user; password hashes and internal fields are excluded.

## 4. Cryptographic keys and policy

### `GET /api/crypto/algorithms` (**implemented in Phase 7**)

- **Purpose:** return the closed set of explicit security levels, their canonical KEM mappings, descriptions, and configured default.
- **Authentication:** required.
- **Response:** a three-item list for LOW/ML-KEM-512, STANDARD/ML-KEM-768, and HIGH/ML-KEM-1024.
- **Rules:** informational only; clients cannot invent an algorithm or mapping.

### `POST /api/crypto/keys/ensure` and `POST /api/crypto/keys` (**implemented in Phase 7**)

- **Purpose:** provision the caller's initial server-managed ML-KEM key when upgrading an existing account.
- **Authentication:** required; rate-limited.
- **Body:** none. Phase 7 idempotently ensures that the authenticated user has one active key for every supported ML-KEM algorithm.
- **Response:** a list of the three active public-only key resources. Repeated calls return the same keyset; a concurrent uniqueness conflict returns `409` and is safe to retry.
- **Rules:** caller only; private key and protection metadata never leave the backend. Rotation is not implemented.

`POST /crypto/generate-keys` from the initial sketch is represented by this resource-oriented endpoint.

### `GET /api/crypto/keys/me` (**implemented in Phase 7**)

- **Purpose:** return the caller's active ML-KEM public-key metadata.
- **Authentication:** required.
- **Response:** a canonical-order list of active public-only key resources; `404` when no setup exists.
- **Rules:** caller only; no encrypted private key, nonce, master-key data, shared secret, or KEK.

### `GET /api/crypto/public-key/{user_id}` (**implemented in Phase 7**)

- **Purpose:** retrieve a recipient's active public key needed for an authorized share workflow or display fingerprint.
- **Authentication:** required.
- **Query:** required allow-listed `algorithm` selection, defaulting to `ML-KEM-768` for compatibility.
- **Response:** the exact requested public-only key metadata using canonical Base64 for JSON transport.
- **Rules:** authentication required and a known UUID is required; a missing exact algorithm returns `404` and never falls back. Sharing resolves recipient keys internally. Rate limits remain deployment hardening.

### `GET /api/security/options` (**implemented in Phase 8**)

- **Purpose:** return allow-listed selection modes, sensitivities, document categories, ranked levels, KEM mappings, and current policy version.
- **Authentication:** required.
- **Rules:** contains no secrets or mutable client authority; backend remains authoritative.

### `POST /api/security/recommend` (**implemented in Phase 8**)

- **Purpose:** preview deterministic policy selection before upload.
- **Authentication:** required.
- **Body:** file name, byte size, MIME type, optional sensitivity, and optional document category; no file content.
- **Response:** minimum/recommended/selected preview level, mapped algorithm, policy version, safe rule results/reasons, and override state.
- **Rules:** advisory only; upload recomputes and enforces policy. Client cannot use a preview to bypass later policy.

## 5. Files

### `POST /api/files/upload` (**implemented through Phase 8**)

- **Purpose:** upload one file, encrypt it server-side, and create owner and crypto metadata.
- **Authentication:** required.
- **Request:** `multipart/form-data` with `file`, `selection_mode`, and mode-appropriate `security_level`, `sensitivity`, and `document_category`. Legacy omission remains MANUAL/STANDARD.
- **Response:** adds `post_quantum_protected: true`, the exact `security_level`, exact `kem_algorithm`, and `crypto_version: 2` without exposing envelope material.
- **Rules:** recompute the deterministic decision, reject contradictory AUTO input or RECOMMEND downgrade, require the owner's exact mapped key, then use the unchanged encryption pipeline. Policy errors fail before ciphertext or database state is committed.

### `GET /api/files/{file_id}/security-decision` (**implemented in Phase 8**)

- **Purpose:** explain why a new file received its stored level.
- **Authentication/authorization:** owner only; unrelated users receive `404`.
- **Response:** mode, minimum, recommendation, final level, KEM, policy version, rules/reasons, and override flag.
- **Historical behavior:** returns `409` when a pre-Phase-8 file has no recorded decision.

### `GET /api/files` (**implemented through Phase 5**)

- **Purpose:** list files owned by the caller.
- **Authentication:** required.
- **Query:** bounded `limit` (default 20, maximum 100) and nonnegative `offset`.
- **Response:** paginated owner-safe file summaries including encryption status and content algorithm.
- **Rules:** repository query always scoped by `owner_id = actor.id`; no object key/path or key envelope bytes.

### `GET /api/files/{file_id}` (**implemented through Phase 5**)

- **Purpose:** obtain authorized metadata.
- **Authentication:** required.
- **Response:** safe owner metadata including encryption status; no owner ID, stored filename, storage path, nonce, or wrapped key.
- **Rules:** owner only. Missing and other-owner IDs share one `404` response.

### `GET /api/files/{file_id}/download` (**implemented through Phase 5**)

- **Purpose:** authorize the owner, unwrap the file key, authenticate/decrypt the stored ciphertext, and return the original bytes.
- **Authentication:** required.
- **Response:** file response with sanitized original filename in `Content-Disposition`.
- **Rules:** version 1 uses the Phase 4 direct master unwrap. Version 2 loads the exact recorded user key, decrypts its private seed, decapsulates, derives the KEK, then authenticates both wrapping and content. Integrity/wrong-key/KEM failure returns controlled `422`; Phase 3 plaintext returns `409`.

### `DELETE /api/files/{file_id}` (**implemented through Phase 5**)

- **Purpose:** owner-requested deletion using a recoverable state transition.
- **Authentication:** required.
- **Response:** `204` after synchronous metadata deletion and best-effort staged object cleanup.
- **Rules:** owner only; one-to-one crypto metadata cascades with the file row; an already-missing physical object does not prevent stale metadata cleanup; missing and unauthorized records return `404`.

## 6. Sharing

### `POST /api/files/{file_id}/share`

- **Purpose:** grant read access and create a recipient-specific key envelope.
- **Authentication:** required.
- **Body:** `{ "recipient_id": "uuid" }`.
- **Response:** `201` with share ID, safe recipient summary, permission, status, effective KEM algorithm/key fingerprint, created time.
- **Rules:** owner only; active recipient and compatible key; no duplicate active share; never return KEM shared secret, KEK, file key, private key, or wrapped-key plaintext. The backend resolves and binds the recipient key.

The share signature and recipient envelope are created in the same transaction.

### `GET /api/shares/received`

- **Purpose:** list files shared with the caller.
- **Authentication:** required.
- **Response:** paginated active and revoked historical share summaries with safe sender/file metadata.
- **Rules:** query scoped by `recipient_id = actor.id`; revoked grants remain visible but cannot be downloaded.

### `GET /api/shares/sent`

- **Purpose:** list shares created for files owned by the caller.
- **Authentication:** required.
- **Response:** paginated share summaries including recipient-safe identity, status, and times.
- **Rules:** scope through current file ownership/sender; no key material.

### `POST /api/shares/{share_id}/revoke`

- **Purpose:** revoke a particular grant and disable its envelope for future retrieval.
- **Authentication:** required.
- **Body:** optional `{ "reason": "short explanation" }`.
- **Response:** `200` with the current revoked share, including on an idempotent retry.
- **Rules:** file owner only; target share must belong to file; atomically revoke share/envelope and audit; owner envelope cannot be revoked here.

The stable share ID avoids ambiguity across old revoked and newly re-created grants.

## 7. Benchmarks

Phase 13 deliberately exposes **no benchmark-run API**: an expensive remote POST would create an avoidable denial-of-service surface. Run the bounded CLI locally and import its `results.json` in the protected `/benchmarks` frontend page. The browser reads the file locally and does not upload it. No `GET /api/benchmarks` route or benchmark database table is currently implemented. See [Benchmarking](BENCHMARKING.md).

Phase 14 likewise runs through an offline CLI and imports completed `adaptive_vs_fixed.json` locally on the same page. It adds no remote experiment-run API. See [Adaptive evaluation](ADAPTIVE_EVALUATION.md).

## 8. Health

### `GET /system/health`

- **Purpose:** liveness only.
- **Authentication:** none.
- **Response:** minimal `{ "status": "ok" }`; no versions, dependency URLs, algorithms, paths, exceptions, or secrets.
- **Rules:** a separate protected readiness/diagnostics endpoint may test DB/storage/KMS dependencies for operators.

## 9. Status-code baseline

| Code | Use |
| --- | --- |
| `200` | Successful read/login/refresh |
| `201` | Resource created |
| `202` | Accepted bounded asynchronous operation |
| `204` | Successful idempotent revoke/delete with no body |
| `400` | Safe malformed semantic request |
| `401` | Missing/invalid authentication |
| `403` | Authenticated but action globally forbidden; avoid where it leaks resource existence |
| `404` | Missing or inaccessible protected resource |
| `409` | Safe state/uniqueness conflict |
| `413` | Upload too large |
| `415` | Unsupported media type under policy |
| `422` | Structured field validation failure |
| `429` | Rate limit/quota exceeded |
| `500` | Generic internal/crypto/storage failure with correlation ID and no secrets |
| `503` | Required provider/dependency unavailable; no downgrade |

## 10. Endpoint security checklist

Phase 15 adds authenticated read-only `GET /api/dashboard/summary`, `GET /api/dashboard/file-share-counts?file_ids=<uuid>` (up to 20 owner file IDs), `GET /api/research/benchmarks/latest`, and `GET /api/research/adaptive/latest`. The first two derive the user exclusively from the token and return only aggregate/safe metadata. Research endpoints return complete existing synthetic exports or 404; they never start benchmark work. Authenticated user search also returns safe algorithm-readiness identifiers (not public-key bytes) for the share dialog. See [UI dashboard](UI_DASHBOARD.md).

Every endpoint definition must specify authentication, actor derivation, object authorization, input bounds, rate limit, idempotency/retry behavior, audit event, safe error mapping, response-field allow-list, and secret-redaction tests before implementation is considered complete.

## 11. Phase 6 implemented sharing API

| Endpoint | Authorization | Result |
| --- | --- | --- |
| `GET /api/users/search?q=...&limit=...` | Authenticated active user | Name/email partial search; 3–100 non-space characters; limit 1–20; excludes caller; safe identity and `crypto_ready` only |
| `POST /api/files/{file_id}/share` | Authenticated file owner | Creates one `READ`/`ACTIVE` recipient envelope from `{ "recipient_id": "uuid" }` |
| `GET /api/shares/received` | Authenticated recipient | Caller’s active received shares only |
| `GET /api/shares/sent` | Authenticated sender | Caller’s active sent shares only |
| `GET /api/shares/{share_id}` | Sender or recipient | Safe file/sender/recipient/status metadata |
| `GET /api/shares/{share_id}/download` | Recipient only | Authenticated binary download with original UTF-8 filename |

The JWT actor is always the sender; clients cannot submit `sender_id` or `owner_id`. Self-share is `400`; missing/inactive recipient key and duplicate share are `409`; missing, unowned, or unrelated objects use `404`; integrity failures use a generic `422`. Responses never expose KEM ciphertext, salts, nonces, wrapped keys, private-key records, storage paths, or other recipients.

| Action | Owner/sender | Intended recipient | Unrelated user |
| --- | --- | --- | --- |
| View/download/delete owned file | Allow | Deny | Deny |
| Create share | Allow for owned file | Deny | Deny |
| View sent share | Allow | N/A | Deny |
| View received share | N/A | Allow | Deny |
| View one share’s metadata | Allow | Allow | Deny |
| Download through recipient envelope | Deny | Allow | Deny |

