# Requirements

## 1. Scope and terminology

This document defines the target product and the Phase 0 design baseline. Requirements marked **Future** are architectural targets for later roadmap phases; none are implemented in Phase 0.

The terms encryption, key encapsulation, key derivation, hashing, authentication, authorization, and digital signatures have distinct meanings:

- **Symmetric encryption:** AES-256-GCM protects file bytes and provides ciphertext integrity/authenticity under the file key.
- **Key encapsulation:** ML-KEM establishes a shared secret using a recipient public key; it does not encrypt files.
- **Key derivation:** a standard KDF turns a shared secret into a purpose-bound key-encryption key (KEK).
- **Hashing:** SHA-256 may identify or verify data in experiments but is not authenticated encryption.
- **Authentication:** establishes the application user's identity; initially JWT-based after password verification.
- **Authorization:** determines which authenticated identity may perform an action on a resource.
- **Digital signature:** Phase 11 ML-DSA sender authenticity and signed package metadata integrity; it is not supplied by AES-GCM or ML-KEM.

Normative keywords **MUST**, **SHOULD**, and **MAY** describe target behavior.

## 2. Phase 0 deliverables

| ID | Requirement | Phase 0 acceptance criterion |
| --- | --- | --- |
| P0-01 | Define scope and requirements | Functional and non-functional requirements are documented with explicit phase boundaries. |
| P0-02 | Define modular architecture | Components, interfaces, dependencies, and storage abstraction are documented. |
| P0-03 | Define security and trust models | Threats, trust assumptions, mitigations, limitations, and key custody are explicit. |
| P0-04 | Define data and API designs | Proposed entities, constraints, endpoint contracts, and authorization rules are documented. |
| P0-05 | Define crypto workflows | Encryption/decryption, multi-recipient envelopes, failure behavior, and crypto agility are documented. |
| P0-06 | Define research strategy | Adaptive policy and benchmark experiment are measurable and avoid unsupported claims. |
| P0-07 | Define roadmap | Only Phase 0 is marked current; implementation is deferred. |

## 3. Functional requirements (future)

### Identity and access

- **FR-001:** A user MUST be able to register with a unique normalized email address and a password.
- **FR-002:** A user MUST be able to authenticate and receive short-lived access credentials.
- **FR-003:** Passwords MUST be stored only as salted outputs of an approved password-hashing library configured for Argon2id (preferred) or bcrypt.
- **FR-004:** An authenticated user MUST be able to obtain their own profile.
- **FR-005:** The backend MUST enforce object-level authorization independently of frontend controls.

### File lifecycle

- **FR-010:** Only authenticated users MAY upload files.
- **FR-011:** The system MUST validate size, filename, and permitted content policy before storage and MUST generate its own storage identifier instead of trusting a client path.
- **FR-012:** Each file MUST be encrypted with a fresh, randomly generated 256-bit AES key using AES-GCM.
- **FR-013:** The encrypted object MUST be stored through a storage interface supporting local development storage and future object storage.
- **FR-014:** A file owner MUST be able to list and view metadata for owned files.
- **FR-015:** Decryption MUST release no plaintext output if AES-GCM authentication fails.

### Keys and sharing

- **FR-020:** Each active ML-KEM user key version MUST identify its exact algorithm/parameter set.
- **FR-021:** The target system MUST support ML-KEM-512, ML-KEM-768, and ML-KEM-1024 through a provider abstraction.
- **FR-022:** Only a file owner MAY create or revoke a share for that file.
- **FR-023:** One encrypted file object SHOULD serve all recipients; each recipient MUST receive a separate key envelope.
- **FR-024:** A recipient envelope MUST bind the file, recipient, key versions, algorithms, and policy-relevant context.
- **FR-025:** Only the owner or an active authorized recipient MAY retrieve the data required to decrypt a file.
- **FR-026:** Phase 12 revocation MUST prevent later retrieval of ciphertext/key material through the application, but the system MUST NOT claim to revoke plaintext or keys already obtained.
- **FR-027:** Users MUST NOT modify another user's cryptographic keys.
- **FR-028:** Key rotation MUST preserve the ability to identify historical key versions needed for existing envelopes; deletion MUST be blocked or migrated while referenced.

### Adaptive policy and crypto agility

- **FR-030:** A deterministic `SecurityPolicyEngine` MUST classify inputs and recommend an algorithm according to versioned configuration.
- **FR-031:** Initial labels MUST include `LOW`, `STANDARD`, and `HIGH`; their algorithm mapping MUST be versioned and subject to deployment minimums.
- **FR-032:** The engine MUST log a non-secret reason code, policy version, inputs used, and selected algorithm.
- **FR-033:** User preference MAY strengthen a result but MUST NOT weaken an organization or system minimum.
- **FR-034:** Application services MUST depend on provider interfaces and algorithm identifiers rather than directly on one ML-KEM library.
- **FR-035:** Envelope and metadata formats MUST be versioned so cryptographic algorithms can change without rewriting stored files.
- **FR-036:** The architecture MUST allow an explicit hybrid strategy combining X25519 and ML-KEM secrets through a reviewed construction; Phase 10 implements the versioned hybrid profile.
- **FR-037:** The architecture MUST keep ML-DSA signature providers, signing-key purpose, and versioned FILE/SHARE signature metadata separate from confidentiality suites; Phase 11 implements this without claiming historical unsigned rows were signed.

### Audit and benchmarking

- **FR-040:** Security-relevant events MUST be auditable without logging passwords, tokens, private keys, AES keys, shared secrets, derived keys, raw confidential content, or wrapped-key plaintext.
- **FR-041:** Benchmark runs MUST record environment and implementation versions alongside timings and sizes.
- **FR-042:** Benchmark timing SHOULD use a monotonic high-resolution clock with warm-up, repeated trials, and summary statistics.
- **FR-043:** Benchmark data MUST distinguish primitive-only timings from end-to-end application latency.
- **FR-044:** The benchmarking comparison MUST support a documented classical baseline and each ML-KEM parameter set; the Phase 14 paired policy comparison MUST keep PQ-only and hybrid adaptive/fixed-HIGH tracks separate.

## 4. Security requirements

- **SR-001:** Production transport MUST use TLS/HTTPS even though application data is encrypted at rest.
- **SR-002:** AES-GCM nonces MUST be unique for a given key. The planned default is a fresh 96-bit nonce from an operating-system CSPRNG for each encryption operation.
- **SR-003:** File keys MUST never be reused across unrelated files.
- **SR-004:** Recipient envelope wrapping MUST use a distinct derived KEK and fresh wrapping nonce per envelope.
- **SR-005:** Security-relevant metadata MUST be authenticated as canonical AAD or covered by a Phase 11 signature where appropriate.
- **SR-006:** JWT signing keys, server key-encryption keys, database credentials, and storage credentials MUST be supplied through a secret-management/configuration boundary, never source code.
- **SR-007:** Private keys stored by the initial server-managed design MUST be encrypted at rest under a key not stored in the same database.
- **SR-008:** All cryptographic comparisons and token verification MUST use maintained libraries and safe library APIs.
- **SR-009:** Authorization failures SHOULD avoid revealing whether an inaccessible resource exists.
- **SR-010:** Rate limiting and abuse controls MUST protect login, registration, upload, key generation, share, and download operations.
- **SR-011:** Files and metadata MUST be validated with explicit size limits and bounded processing.
- **SR-012:** The design MUST fail closed on unknown algorithm identifiers, unsupported versions, missing metadata, decapsulation errors, unwrapping failures, and authentication failures.
- **SR-013:** No partially decrypted file MAY be returned or committed as a successful download.
- **SR-014:** Backup, recovery, and deletion procedures MUST preserve the security classification of encrypted key material and secrets.

## 5. Quality requirements

| Area | Requirement |
| --- | --- |
| Maintainability | Services have focused responsibilities; routing, business logic, persistence, storage, and cryptography remain separate. |
| Testability | Provider and repository interfaces support unit fakes; official algorithm test vectors and negative tamper tests are planned. |
| Portability | Development uses simple local processes; Docker is not required. Configuration is environment-driven. |
| Reliability | Database and object-store state transitions are idempotent or recoverable; orphan cleanup is explicit. |
| Observability | Structured logs use correlation IDs and reason codes, redact secrets, and avoid filenames when policy classifies them as sensitive. |
| Performance | Large-file encryption SHOULD stream/chunk through a reviewed format/library rather than load entire files into memory; the exact format is a later implementation decision. |
| Accessibility | Planned React pages SHOULD follow keyboard, contrast, labels, and error-message accessibility practices. |
| Compatibility | Exact algorithms, providers, format versions, and dependency versions are recorded with generated artifacts and benchmarks. |

## 6. Planned user-facing pages

Login, Register, Dashboard, Upload File, My Files, Shared With Me, Share File, Security Settings, and Benchmark Dashboard.

## 7. Research requirements

The principal question is: **Can adaptive selection of post-quantum security configurations reduce computational and communication overhead compared with always using ML-KEM-1024 while still satisfying a selected, versioned security policy?**

The initial adaptive mechanism is deterministic policy, not machine learning. The study will compare fixed ML-KEM-1024 and adaptive selection across the same workloads, hardware, library versions, network conditions, and repetitions. Measurements include key generation, encapsulation, decapsulation, AES encryption/decryption, total share latency, key and ciphertext sizes, encrypted-file overhead, memory where practical, and network bytes. Results must report uncertainty/dispersion and separate algorithm cost from I/O and application cost.

The claim under study is policy compliance plus performance/communication impact. It is not a claim that a low-sensitivity file intrinsically requires weaker mathematics or that the project creates a new cryptographic algorithm.

## 8. Explicit non-goals for the initial implementation

- Zero-knowledge or true end-to-end encryption while the server manages private keys and processes plaintext.
- Protection of plaintext after an authorized recipient saves or copies it.
- Endpoint malware protection, screen capture prevention, or malicious-recipient DRM.
- Traffic-analysis resistance, anonymity, or concealment of all metadata.
- A custom cryptographic primitive, custom hybrid combiner, or custom file-encryption format without review.
- Production certification or formal proof of the complete application.

## 9. Phase 0 completion criteria

Phase 0 is complete when all documents linked from the root README are internally consistent, only documentation exists, Phase 1+ behaviors are described but not implemented, and the roadmap identifies Phase 1 as the exact next step.

## 10. Phase 8 implementation status

The system now supports explicit `LOW -> ML-KEM-512`, `STANDARD -> ML-KEM-768`, and `HIGH -> ML-KEM-1024` selection plus deterministic MANUAL, RECOMMEND, and AUTO workflows. Phase 10 additionally offers explicit `PQ_ONLY` or `HYBRID` X25519 + ML-KEM suite mapping without changing the adaptive level rules. Phase 11 adds independent ML-DSA sender signatures to new files and shares. Policy `adaptive-v1` evaluates explicit metadata through centralized sensitivity, category, secret-extension, and safe-default rules; numeric ordering selects the strongest minimum and generates stored explanations. Recommendations can be strengthened but not weakened below the required level. Sharing uses the stored suite without reevaluation. Phase 12 revokes application share grants; Phase 13 provides offline synthetic benchmarks and exports. Content inspection, machine learning, identity-key rotation, and advanced revocation remain future or out of scope.

