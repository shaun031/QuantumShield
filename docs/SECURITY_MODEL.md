# Security Model

## Phase 12 revocation boundary

The owner can revoke one recipient's future QuantumShield downloads. The share becomes REVOKED, its envelope inactive, and an audit event retained; recipient download checks this before ML-DSA verification or private-key recovery. Revocation does not retract already delivered plaintext/key material, change the owner's file, or prevent full database rollback. A retained revocation audit marker also rejects a share whose status and envelope are reset without deleting the event. See [Access revocation](ACCESS_REVOCATION.md).

## Phase 11 sender-authenticity boundary

ML-DSA signatures bind the expected sender and recorded key version to canonical file/share metadata, recipient identity, full key-package digest, and actual ciphertext SHA-256. Signed package changes fail before decryption. A required missing signature fails closed; pre-migration unsigned rows remain explicitly `LEGACY_UNSIGNED`. Authorization is still required and the trusted backend/master key remain in scope. Signatures do not prevent replay, full database rollback, key compromise, or a privileged database attacker clearing a signature-required flag and signature row. See [Digital signatures](DIGITAL_SIGNATURES.md).

## Phase 10 hybrid threat boundary

Hybrid owner/share envelopes require both an exact ML-KEM key version and an exact X25519 key version. The suite/architecture/algorithm/recipient metadata is validated before recovery and authenticated by HKDF context and AES-GCM wrapping AAD; missing keys or tampered components fail without downgrade. This mitigates reliance on a single key-establishment family during transition, but the trusted backend and master key can still recover private keys and plaintext. X25519 alone is not quantum-resistant; hybrid mode adds complexity and overhead. Phase 10 itself introduced no sender signature or rollback protection; Phase 11 adds signatures but still no rollback protection. See [Hybrid cryptography](HYBRID_CRYPTO.md).

## Crypto-agility security rule

Crypto agility does not authorize user-defined algorithms. Only trusted registry suites are usable; only ACTIVE suites protect new data. Unknown and DISABLED suites fail closed, while DEPRECATED suites may decrypt historical records but cannot encrypt. Suite/algorithm/security-level/recipient-key inconsistencies are treated as algorithm-confusion attempts and are rejected without downgrade, guessing, or trying multiple providers.

## 1. Security objectives

QuantumShield's target security properties are:

1. **File confidentiality at rest:** storage or database theft alone should not reveal plaintext file contents.
2. **Ciphertext integrity/authenticity:** modified encrypted file bytes or authenticated metadata must fail AES-GCM verification.
3. **Recipient isolation:** each recipient uses a separate envelope tied to that recipient and key version.
4. **Application access control:** only authenticated owners and active authorized recipients can retrieve permitted resources.
5. **Post-quantum key establishment:** ML-KEM protects recipient envelope key establishment against the currently understood future quantum threat assumptions of the standardized construction and correct implementation.
6. **Crypto agility:** algorithms and formats can be versioned and replaced without changing the file/sharing domain model.
7. **Accountability:** security-relevant decisions are auditable without recording secret material.

These objectives do not turn the initial trusted-backend design into end-to-end encryption.

## 2. Assets and classifications

| Asset | Classification | Notes |
| --- | --- | --- |
| Password | Secret, transient | Exists during registration/login handling only; never logged or stored. |
| Password hash | Sensitive | Offline guessing target; database access must be restricted. |
| JWT signing secret/private key | Critical secret | Outside database/source; rotation and access control required. |
| User ML-KEM public key | Public cryptographic material | Integrity and ownership binding still matter. |
| User ML-KEM private key | Critical secret | Initial version stores only an encrypted blob or external key reference. |
| Server master KEK/KMS authority | Critical secret | Must not be colocated with encrypted private keys in the same database. |
| AES file key | Critical secret, transient | Fresh per file; stored only in wrapped form inside envelopes. |
| ML-KEM shared secret | Critical secret, transient | KDF input; never persisted. |
| Derived KEK | Critical secret, transient | Used only to wrap/unwrap a file key; never persisted. |
| Wrapped AES file key | Sensitive ciphertext | Safe only with correct AEAD, context binding, and private-key protection. |
| File ciphertext | Confidential ciphertext | May be placed on untrusted storage; availability is not guaranteed there. |
| Nonces, tags, KEM ciphertext, salt, algorithm IDs | Non-secret security metadata | Must be authentic/bound to context even though secrecy is unnecessary. |
| Original filename, MIME type, file size, ownership/share graph | Sensitive metadata | Can reveal content or relationships; expose only when authorized. |
| Audit and benchmark records | Internal/sensitive | Must be redacted and access-controlled. |

## 3. Trust boundaries and assumptions

### Trusted for the initial implementation

- Users trust the delivered React client and FastAPI backend implementation.
- The backend host/runtime can see uploaded plaintext, recovered plaintext, user passwords transiently, private keys transiently after unwrapping, and AES keys transiently.
- Administrators with access to the running backend plus its master-key authority are highly privileged.
- Maintained crypto libraries correctly implement selected algorithms when used through their safe APIs.
- The operating system CSPRNG provides adequate randomness.
- PostgreSQL correctly enforces configured constraints/transactions and is access-controlled.
- Production TLS termination, configuration, and certificate validation are correct.

### Not inherently trusted

- Clients' claims, identifiers, filenames, paths, MIME types, policy labels, and authorization assertions.
- Local/cloud encrypted-file storage.
- The network between the user and service; HTTPS remains mandatory.
- Database contents in a database-only compromise.
- Public keys for confidentiality; public means publishable, not that an unverified key-to-user binding may be trusted.

### Trust limitation

A full backend compromise while private keys/master-key access and ciphertext are available can expose files. Server logs, process memory, endpoint malware, and administrators are outside the cryptographic protection supplied by the initial server-managed design. Backups inherit the sensitivity of the data they contain.

## 4. Private-key custody decision

### Option A — server-managed private keys

The backend generates or receives user ML-KEM key pairs. It stores public keys normally and stores private keys only as an authenticated-encrypted blob under a server-controlled KEK, or stores a KMS/HSM reference. The KEK is outside PostgreSQL. The backend unwraps a private key only for an authorized operation and minimizes its lifetime in memory.

Advantages:

- Simpler React client and recovery experience.
- Consistent library support and key/version migrations.
- Easier server-side sharing, decryption, and benchmarking.
- Better fit for a bounded college-project implementation.

Disadvantages:

- Backend compromise can disclose private keys and plaintext.
- Administrators/key service are inside the trust boundary.
- Not zero-knowledge and not true end-to-end encryption.
- Account recovery, master-key rotation, backup, and audit become sensitive operational responsibilities.

### Option B — client/user-controlled private keys

Private keys are generated and retained on the client or in a user-controlled secure store. The backend stores public keys and encrypted file/envelope material but does not possess the private key required for decapsulation.

Advantages:

- Stronger separation from server compromise and a plausible end-to-end design when all plaintext crypto remains client-side.
- Server administrators cannot decrypt solely from server data.

Disadvantages:

- Browser/runtime ML-KEM interoperability and secure local storage are harder.
- Lost keys can permanently lose data unless a carefully designed recovery mechanism exists.
- Multi-device synchronization, rotation, revocation, migration, and UX are substantially harder.
- Server-side benchmarking and content classification must be redesigned or moved client-side.

### Phase decision

Use **Option A for the initial college-project version**, with encrypted private keys and an external master-key/configuration boundary. Document every UI and report as server-managed encrypted file sharing, not end-to-end or zero-knowledge. Option B can be researched after the server-mediated system is correct and tested.

## 5. Authentication model

Phase 2 implements the following deliberately small model:

- Email is trimmed and case-folded before lookup and is protected by a database unique constraint.
- Passwords are accepted only at 8–128 characters and are hashed with `pwdlib`'s recommended Argon2id hasher. Plaintext passwords and password hashes are never returned or logged.
- Unknown email, wrong password, and inactive account login attempts receive the same safe `401` response. A dummy hash verification reduces the obvious unknown-user timing difference.
- Access tokens use HS256 with server-controlled key material and a 30-minute default lifetime. Verification fixes the allowed algorithm and requires `sub`, `iat`, `exp`, and `type=access`; the subject must parse as the UUID of an existing active user.
- JWTs contain no password, profile data, cryptographic key, or other private claims.
- The React client stores the access token in `sessionStorage` and sends it as a bearer token. This limits persistence to a tab session but does not protect against same-origin script injection/XSS.
- Logout deletes the client copy only. With no server-side session or deny-list, a copied token cannot be revoked before expiry. Changing the signing secret invalidates all outstanding tokens.
- Rate limiting/backoff, refresh tokens, server-side revocation, MFA, password recovery, and email verification are not implemented. Public exposure is unsafe until brute-force controls and deployment-layer protections are added.
- Argon2 parameter upgrades can be recognized through the password library, but automatic rehash persistence is deferred until the project defines a versioned password-policy migration procedure.

## 6. Authorization model

Initial role: `USER`. Administrator capabilities are out of initial scope.

| Action | Rule |
| --- | --- |
| Upload | Authenticated, active user only |
| List own files | `file.owner_id == actor.id` |
| View file metadata | Phase 3: owner only. Later: recipient with an active non-revoked share and least-privilege fields |
| Share | Owner only; recipient must be active and have a compatible active public key |
| Download/decrypt | Phase 5: owner-only versioned ML-KEM/AES authenticated decryption. Phase 6: active recipient envelope |
| Revoke share | Owner only; cannot revoke owner envelope through normal sharing API |
| View sent shares | Owner/sender only |
| View received shares | Receiver only |
| Generate/rotate own key | Same authenticated user; policy-controlled |
| Change another user's key | Never allowed to a normal user |
| Read benchmarks | Authenticated user for permitted aggregate records; raw/environment data policy may be narrower |

Every rule is enforced after resolving the authenticated user from the token. User IDs in request bodies never establish the actor. Unauthorized and nonexistent resources should generally return the same external result where enumeration is a concern.

### Phase 5 post-quantum key-establishment boundary

- Every new local object is AES-256-GCM ciphertext under a unique random file key. The explicitly selected ML-KEM-512/768/1024 provider establishes a transient shared secret, HKDF-SHA256 derives a KEK, and AES-GCM wraps that file key.
- The master key protects server-managed user ML-KEM private seeds. It no longer directly wraps new version-2 file keys, while version-1 compatibility retains the Phase 4 path.
- Storage-only compromise does not reveal plaintext. Database-only compromise exposes public keys, encrypted private keys, KEM ciphertexts, wrapped keys, nonces/salts, metadata, and plaintext SHA-256 values—but not the master key or raw secrets.
- Combined database/storage theft still requires protected private-key recovery. Master-key plus database/storage compromise can expose files because the backend is a trusted decryption party.
- Storage keys use server-generated UUID names in owner-separated directories and are containment-checked beneath one configured root. Directory separation is organization, not authorization.
- The original client filename is reduced to a safe display basename and never controls a filesystem path. Client MIME values and extensions remain untrusted advisory metadata.
- Uploads are bounded to 25 MB by default and encrypted as a complete in-memory value. Framework-managed upload spooling may temporarily hold plaintext; there is no antivirus, content-disarm, quota, or distributed storage protection.
- SHA-256 is calculated for exact-output checks. As an unkeyed plaintext hash, it may leak equality and does not replace AES-GCM authentication.
- Storage is never exposed as a public static directory. Every retrieval resolves the authenticated actor and an owner-scoped database record.
- A legacy Phase 3 database row without crypto metadata is labeled unencrypted and blocked from normal download with `409`; it is never passed into the AES decryptor.
- Phase 4 version-1 rows remain explicitly decryptable; Phase 5 never infers a format from missing fields.
- Production transport must use HTTPS because encryption is server-side, not end-to-end. Python cannot guarantee zeroization of immutable plaintext/key buffers.

## 7. Cryptographic metadata binding

Metadata is not secret but can redirect or weaken decryption if tampered with. The file AEAD and key-envelope AEAD use deterministic, versioned canonical AAD. The envelope AAD should bind at minimum:

- format/envelope version;
- file ID and immutable file crypto-metadata ID/version;
- owner ID and intended recipient ID;
- recipient public-key record ID/fingerprint;
- file encryption algorithm;
- KEM and KDF algorithm identifiers;
- selected policy/security level and policy version where required;
- wrapping algorithm and purpose label.

The serialized form must be unambiguous (for example canonical CBOR or a rigorously specified length-prefixed form), not ad hoc string concatenation or ordinary JSON whose serialization may vary. Database authorization still applies; AAD is not a substitute for it.

## 8. Revocation semantics

Revocation atomically marks a grant/envelope unavailable to normal retrieval and records `revoked_at`, actor, and audit reason. The backend checks this state before returning envelope/ciphertext material and again before releasing server-decrypted plaintext where feasible.

Revocation cannot:

- erase plaintext already downloaded;
- make a copied AES key unusable;
- remove copied ciphertext/envelopes from an external recipient;
- control screenshots, backups, or later redistribution.

Stronger forward revocation for remaining users would require generating a new file key, re-encrypting the file, and issuing new envelopes—and still would not retract older plaintext/ciphertext plus keys. This is not claimed for the initial version.

## 9. Failure behavior

| Failure | Required behavior |
| --- | --- |
| Wrong private key / ML-KEM decapsulation mismatch | Do not expose internal oracle details; derivation/unwrap or authentication fails and returns a generic decryption failure, audit reason internally. |
| Tampered file ciphertext, nonce, tag, or file AAD | AES-GCM verification fails; release no plaintext; record a redacted integrity event. |
| Tampered recipient envelope metadata | Envelope AAD verification or lookup consistency fails; do not recover/use the file key. |
| Invalid authentication tag | Stop and release no partial plaintext. |
| Revoked access | Deny retrieval/decryption, even if metadata is otherwise valid. |
| Missing/unknown version or metadata | Fail closed; do not guess defaults. |
| Unsupported provider/algorithm | Fail closed with an operational error; do not downgrade silently. |
| Object/DB inconsistency | Mark unavailable/pending repair; never substitute another path/object. |

Externally observable errors should minimize oracle and enumeration leakage, while internal logs retain a correlation ID and non-secret reason.

## 10. Project-wide security rules

- Never store passwords in plaintext.
- Never use ECB mode.
- Never create a custom encryption algorithm.
- Never hardcode encryption keys or production secrets.
- Never reuse an AES-GCM nonce with the same key.
- Never use predictable randomness for keys, nonces requiring unpredictability, tokens, or identifiers used as secrets.
- Never log passwords, password hashes unnecessarily, tokens, JWT signing keys, private keys, AES keys, ML-KEM shared secrets, derived keys, or confidential plaintext.
- Never trust user-supplied file paths or use raw filenames as storage paths.
- Validate and safely render filenames; prevent path traversal and content-disposition injection.
- Use authenticated encryption and verify before releasing plaintext.
- Use maintained cryptographic libraries, standard algorithms, supported parameter sets, and published test vectors.
- Do not permit client-selected arbitrary crypto providers or silent downgrade.
- Separate public identifiers from secret authorization values.
- Apply least privilege to database, storage, secret-manager, filesystem, process, and operator access.

## 11. Privacy and metadata

Encryption does not conceal account identities, share relationships, access time, ciphertext size, approximate original size, IP/network information, or necessarily filenames/MIME types from the trusted service. Minimize collected metadata, set retention periods, authorize metadata endpoints, redact logs, and avoid publishing raw benchmark/user associations. A future privacy review should decide whether original filenames and MIME types need separate field-level encryption.

## 12. Security validation plan

Later phases must include official known-answer/vector tests where applicable; nonce uniqueness tests; negative tag/ciphertext/AAD/envelope tamper tests; wrong-key tests; broken-object tests; path traversal and malicious filename tests; object-level authorization tests; race/revocation tests; rate-limit tests; secret-scanning/log-redaction tests; dependency review; backup/restore tests; and manual review of production configuration. Passing application tests is not a certification of the cryptographic system.

## 13. Phase 6 authorization and privacy controls

- Owner actions use the authenticated user and owner-scoped file lookup; request bodies contain only a recipient UUID.
- Share metadata is visible only to its sender or its one recipient. Recipient listing is caller-scoped and never exposes other recipients of the same file.
- Recipient download is stricter than metadata access: only the intended active-share recipient can use it. Sender/unrelated probes receive the same `404`.
- Authenticated discovery requires at least three non-space characters, caps results at 20, excludes the caller, and returns only ID/name/email/crypto readiness. Rate limiting remains deployment hardening.
- Duplicate file/recipient relationships are rejected in service logic and by a database unique constraint.
- Share context authentication binds recipient identity and exact key version; tampering yields a generic integrity failure and no plaintext.
- Deleting an owned file cascades live shares/envelopes and removes the physical object. It cannot erase recipient copies already downloaded.

## 14. Phase 7 algorithm-selection controls

Phase 7 accepts exactly `LOW`, `STANDARD`, or `HIGH`, mapped respectively to ML-KEM-512, ML-KEM-768, and ML-KEM-1024. The backend persists and validates both values. Upload, owner download, share creation, and recipient download resolve the exact recorded provider and key version; unsupported identifiers, invalid pairs, crossed keys, missing exact recipient keys, and provider failures fail closed with no downgrade.

All three providers are self-tested at startup. The ML-KEM-512 dependency currently describes itself as beta and unsuitable for real-world production, so this remains a research implementation until that provider is replaced or independently validated. The trusted backend/master-key authority can still recover user private material and file plaintext; Phase 7 is not zero-knowledge or end-to-end encrypted.

## 15. Phase 8 adaptive-policy controls

- Policy `adaptive-v1` consumes only explicit metadata: file name/extension, size, MIME type, optional sensitivity, and optional category. It never reads content for classification.
- Independent rules return minimum levels. Explicit numeric ranking selects the strongest; file size cannot weaken any requirement.
- Missing signals default to STANDARD rather than LOW. Unknown enum values and policy exceptions fail the upload instead of downgrading.
- AUTO rejects an explicit level. RECOMMEND rejects confirmation below the required level and permits only equal/stronger choices.
- The backend recomputes decisions during upload and stores versioned rules/reasons; a preview is not trusted as authorization.
- Full classifications and explanations are owner-only because values such as MEDICAL can reveal sensitive metadata. Recipients receive only selected level/KEM information.

Residual risks include dishonest or mistaken labels, misleading file extensions, static project-policy assumptions, and trusted-server compromise. Adaptive selection does not improve the mathematical properties of an ML-KEM parameter set or replace authentication, authorization, encryption, integrity, or key management.

