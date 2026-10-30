# Threat Model

## Phase 16 tested controls and remaining exposure

The controlled regression matrix, methodology, exact test names, findings, and caveats are in [Security testing](SECURITY_TESTING.md). The Phase 16 tests exercise authentication and JWT tampering (T-14), file/share IDOR (T-05/T-06), path confinement and upload bounds (T-12/T-13), AES-GCM and ciphertext substitution (T-03), ML-KEM/hybrid envelope and algorithm mismatch (T-04/T-10/T-23), ML-DSA signing-key binding (T-04), revocation/re-share (T-15/T-20), and object/DB inconsistency plus cleanup (T-21). Secret-log and safe-error tests cover a sample of T-19. These tests used isolated SQLite/temporary storage; they are not a substitute for production PostgreSQL race testing or an external penetration test.

Two low-severity robustness findings were fixed: missing crypto metadata on a signed file no longer masquerades as a legacy plaintext record, and invalid internal storage keys now return controlled integrity errors rather than generic 500s. Neither finding allowed plaintext release. The test evidence does **not** eliminate the residual risks already listed below. In particular, T-09/T-13/T-14 retain no online rate limiting or MFA/token denylist; T-15 cannot undo prior recipient downloads; T-18 still trusts the backend/master key; T-20 still needs external rollback detection; T-17 still needs live dependency and supply-chain review. Classification remains user-provided, MIME remains advisory, and no malware/content inspection is performed.

## Phase 12 revocation threats

| Threat | Phase 12 mitigation | Residual risk |
| --- | --- | --- |
| Revoked recipient retries or guesses an old share ID | Recipient-scoped lookup, status/audit check, inactive envelope check before cryptography, safe 403 only for the former recipient | Previously copied plaintext or keys remain outside application control. |
| Stale recipient package is reused | Each re-share creates a new share ID and fresh envelope; inactive old envelope is never selected | A recipient who retained old materials may decrypt previously copied ciphertext independently. |
| Share status or package state is flipped | Both state fields and the retained revocation audit marker are checked | Full database rollback or removal of all three markers requires external detection. |
| Concurrent revoke/re-share attempts | Conditional ACTIVE→REVOKED update, one active-grant index, unique revocation event | A share attempt racing a revoke may receive a retryable duplicate conflict. |
| Owner revokes the wrong recipient | Explicit UI confirmation names recipient/file and explains consequence | Human mistakes remain possible; no automatic undo/reactivation is provided. |

See [Access revocation](ACCESS_REVOCATION.md). The table below is the original broader threat inventory.

## 1. Scope and method

This Phase 0 threat model covers the planned React client, FastAPI backend, PostgreSQL metadata store, encrypted object storage, cryptographic providers, and server-side key custody. It considers confidentiality, integrity, availability, authentication, authorization, and misuse. It must be revisited at every implementation phase and whenever deployment or key custody changes.

## 2. Assets and adversaries

Primary assets are plaintext files, passwords, tokens, ML-KEM private keys, AES file keys, derived keys, sharing permissions, authenticated metadata, audit records, and service availability.

Considered adversaries include an unauthenticated network attacker, malicious registered user, unauthorized recipient, storage-only intruder, database-only intruder, offline password guesser, supply-chain attacker, malicious/compromised operator, endpoint malware, and a future cryptographically relevant quantum attacker.

## 3. Threats, controls, and residual risk

| ID | Threat | Planned protection | Residual risk / honest limitation |
| --- | --- | --- | --- |
| T-01 | Attacker steals encrypted files from local/object storage | Fresh AES-256-GCM file keys; keys absent from object storage; random object names | Sizes/access patterns remain visible. A backend/master-key compromise can recover keys. Availability is not protected by encryption. |
| T-02 | Attacker intercepts network traffic | Correct TLS/HTTPS, certificate validation, secure token handling; application ciphertext remains encrypted at rest | TLS endpoint/backend remains trusted; metadata and credentials exist in server memory. Misconfigured TLS defeats this layer. |
| T-03 | Attacker modifies file ciphertext | AES-GCM tag verification and bound AAD; fail closed before plaintext release | Deletion/replay/rollback require storage/version/state controls; AEAD alone does not provide availability or freshness. |
| T-04 | Attacker modifies nonce, tag, algorithm, recipient, or KEM metadata | Canonical AAD, versioned envelope, allow-listed algorithm registry, relational consistency checks, Phase 11 FILE/SHARE ML-DSA signatures | A fully compromised authorized backend can create valid new metadata. Database rollback needs operational detection/versioning. |
| T-05 | User tries to download another user's file | JWT authentication; object-level backend authorization; opaque IDs; storage inaccessible directly | Authorization bugs remain a major risk; IDs are not access controls. |
| T-06 | Malicious user shares/revokes someone else's file | Ownership checks using authenticated actor, database constraints/transactions, audit events | Stolen owner session can act as owner until detected/revoked. |
| T-07 | Attacker obtains database contents | Password hashing; encrypted private-key blobs; no plaintext AES/shared/derived keys; ciphertext stored separately; least-privilege credentials | Metadata/share graph and password hashes leak. Offline guessing remains possible. DB plus master KEK or backend access is much worse. |
| T-08 | Attacker knows public keys | Expected property of public-key cryptography; authenticity/ownership binding and key fingerprints/versioning | Replacing a public key could redirect future shares, so write access and binding must be protected/audited. Public keys need integrity, not secrecy. |
| T-09 | Attacker guesses passwords online/offline | Argon2id/bcrypt, unique salts handled by library, strong-password guidance, generic errors, rate limits, monitoring | Weak passwords can still fall to offline guessing; MFA is not in initial scope. |
| T-10 | Receiver/backend uses wrong private key | Exact recipient key-version reference; KEM result fed to context-bound KDF and authenticated key unwrap; generic failure | Some KEM APIs return a pseudorandom secret rather than an explicit decapsulation error, so successful envelope AEAD verification is decisive. |
| T-11 | AES-GCM nonce repeats under one key | Fresh file key per file plus fresh 96-bit CSPRNG nonce; distinct envelope KEKs/nonces; tests and safe library APIs | Random-collision risk is tiny but nonzero; accidental key reuse/import bugs must be prevented. |
| T-12 | Attacker traverses paths or overwrites files | Server-generated object keys, root-confined path resolution, filename normalization for display only, no client paths | Parser/library bugs and OS misconfiguration remain possible. |
| T-13 | Attacker submits huge/malformed files or expensive requests | Request/body limits, quotas, streaming/bounded processing, timeouts, rate limiting, safe parsers | Authorized users may still exhaust resources; capacity controls and monitoring are needed. |
| T-14 | Attacker steals/replays JWT | Short lifetimes, HTTPS, validated claims, token IDs/refresh rotation strategy, secure client storage decision, logout/disable policy | Access tokens remain usable until expiry unless an online denylist/version check is adopted. XSS can steal browser-accessible tokens. |
| T-15 | Receiver accesses after revocation | Backend denies later ciphertext/envelope/key-material retrieval and records revocation | Cannot revoke plaintext, keys, ciphertext, or metadata already copied by the recipient. |
| T-16 | Future quantum computer attacks recorded key establishment | Standardized ML-KEM parameter sets through reviewed libraries; crypto-agile versioning; later hybrid option | No unconditional guarantee: implementations, endpoints, symmetric security, standards evolution, and cryptanalysis remain relevant. |
| T-17 | Malicious dependency or compromised build | Pinned/locked dependencies, provenance and vulnerability review, minimal dependency set, CI tests, release controls | Supply-chain compromise cannot be eliminated; reproducible/verified builds are future hardening. |
| T-18 | Insider or fully compromised backend reads files/keys | Least privilege, encrypted private keys, separate master-key authority, audit/monitoring, minimize plaintext/key lifetime | Initial architecture explicitly trusts backend; it cannot claim secrecy from a sufficiently privileged or compromised server. |
| T-19 | Secrets leak through logs/benchmarks/errors | Central redaction, allow-listed event fields, generic external errors, synthetic benchmark data, tests for secret absence | Crash dumps, tracing agents, and operator diagnostics also need controls. |
| T-20 | Rollback/replay of old envelope or access state | Version IDs, active/revoked state, immutable creation records, transaction checks, audit sequence/time, reject inactive key versions for new shares | Sophisticated database plus backup rollback may need external append-only anchoring, not planned initially. |
| T-21 | File is corrupted/deleted or DB/object become inconsistent | Backups, checks, explicit upload states, idempotent cleanup/reconciliation, encrypted-object hash for operational verification if used | SHA-256 can detect accidental/object mismatch but neither restores availability nor replaces AEAD authenticity. |
| T-22 | Sensitive classification is manipulated | Backend validation; organization minimum; users can strengthen but not bypass policy; policy/reason/version audit | Content classification is fallible. Initial keyword/file-type rules do not understand document semantics. |
| T-23 | Algorithm downgrade or unknown provider is requested | Server allow-list, versioned registry, policy minimum, reject unknown IDs, no silent fallback | Configuration compromise may alter policy; configuration changes need review/audit. |
| T-24 | Recipient redistributes plaintext | Clear user policy and audit of application delivery | Cryptography cannot prevent an authorized recipient from copying plaintext; DRM is out of scope. |

## 4. Attack surfaces

- Registration, login, token refresh, and account/key recovery.
- Upload/download streaming, filenames, MIME handling, and content disposition.
- File/share identifiers and object-level authorization.
- Crypto provider inputs, metadata parsing, serialization, algorithm registry, and error handling.
- Database queries, migrations, backups, and administrative access.
- Local filesystem/object-store configuration and credentials.
- Logs, traces, benchmark exports, crash dumps, and developer tooling.
- Frontend XSS/CSRF exposure depending on final token transport/storage choice.
- Dependency installation, build pipeline, and deployment configuration.

## 5. Out-of-scope or not fully solved

- A compromised user device, malicious browser extension, keylogger, or screen capture.
- A recipient who legitimately receives and then redistributes content.
- Confidentiality from the backend in the initial server-managed-key design.
- Perfect deletion from backups, caches, or third-party storage without explicit lifecycle controls.
- Denial of service by a sufficiently capable adversary.
- Traffic-analysis resistance and concealment of all metadata.
- Cryptographic assurance beyond the selected standards, library implementation, and operational correctness.

## 6. Required review gates

Before the related feature ships, review: key-custody implementation, envelope/AAD specification, ML-KEM provider and vectors, large-file authenticated streaming format, token storage/CSRF model, share/revocation concurrency, storage path confinement, logging redaction, dependency provenance, and production secrets/backups. Any change from server-managed to client-managed keys requires a new threat model, not a label change.

## 7. Phase 6 sharing review

| Threat | Phase 6 mitigation | Residual risk |
| --- | --- | --- |
| Malicious recipient redistributes plaintext | Read-only authorization, delivery logging, no owner mutation rights | An authorized recipient can retain/copy plaintext; cryptography cannot recall it |
| Unauthorized share-ID guessing / IDOR | UUIDs plus database predicates on sender/recipient; recipient-only download; unrelated requests return `404` | Authorization defects remain possible; opaque IDs are not treated as authorization |
| Recipient key mismatch | Envelope records exact key ID/version; deterministic context binds user/key/share/file; GCM wrap authentication fails closed | Server/master-key compromise can use stored keys |
| Tampered share metadata | Context-bound HKDF and AES-GCM key wrap; structural database checks; generic `422`; no plaintext | Availability can still be destroyed; DB rollback protection remains operational work |
| Mass user enumeration | Authentication, three-character minimum, 20-result cap, caller exclusion, safe field allow-list | Distributed authenticated searching can still infer identities; rate limits are not yet implemented |
| Duplicate/concurrent share requests | Pre-check plus unique `(file_id, recipient_id)` constraint and transactional rollback | Caller may observe a safe `409`; no idempotency key yet |
| Shared-file deletion | File/share/envelope database cascade plus staged physical deletion; later download returns `404` | Backups and already-downloaded plaintext are not erased |

## 8. Phase 7 multi-parameter-set review

| Threat | Phase 7 mitigation | Residual risk |
| --- | --- | --- |
| Client requests unknown or mismatched level/algorithm | API accepts a closed security-level enum; backend owns the fixed mapping; database checks bind both values | Application/configuration compromise can still alter behavior and needs operational controls |
| Missing exact recipient key causes downgrade | Share creation requires the recipient's active key for the file's stored algorithm and fails atomically if absent | Availability depends on successful keyset provisioning |
| Ciphertext or key used with another parameter set | Exact provider, key ID, key version, and algorithm-specific byte lengths are checked before decapsulation; unwrap authentication is decisive | A provider defect remains a supply-chain/implementation risk |
| Provider unavailable or self-test fails | Startup fails closed after testing all required providers; no automatic substitution exists | ML-KEM-512 currently relies on a beta dependency and is research-only |
| User selects an unsuitable level | Phase 8 RECOMMEND/AUTO enforce deterministic project-policy minimums; MANUAL remains explicit and recorded | Users can mislabel inputs; project rules are not universal standards |

## 9. Phase 8 adaptive-policy review

| Threat | Phase 8 mitigation | Residual risk |
| --- | --- | --- |
| Policy downgrade through conflicting request fields | AUTO rejects explicit levels; RECOMMEND rejects values below the recomputed minimum | MANUAL intentionally preserves explicit Phase 7 behavior |
| Weak result after policy exception or unknown enum | Closed enums reject unknown values and policy errors fail the upload; no fallback to LOW | Availability depends on correct policy code/configuration |
| One weak rule overrides a strong rule | Explicit numeric ordering takes the maximum of all applicable minimums | Incorrect project rule values can still produce unsuitable policy |
| Recommendation preview is altered or stale | Upload recomputes the policy decision and does not trust preview output | Rules can change between preview/upload; versioning makes the final decision explainable |
| Sensitive classification leaks to recipients | Full policy metadata and decision endpoint are owner-only; share responses expose only selected level/KEM | Trusted backend/database operators can see stored classifications |
| Filename/metadata is misleading | Explanations identify the exact inputs/rules and no claim of semantic content classification is made | Users may accidentally or deliberately misclassify files |

