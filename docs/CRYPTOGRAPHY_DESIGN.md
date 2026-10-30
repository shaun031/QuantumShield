# Cryptography Design

## Phase 12 envelope lifecycle

Revocation changes authorization state, not the AES ciphertext, ML-KEM/X25519 algorithms, or the Phase 11 signature bytes. A recipient envelope is marked inactive and cannot be used by normal download paths. Re-sharing performs fresh encapsulation, salt/nonce generation, and signing. SHARE signature payload v1 continues to authenticate the immutable creation snapshot `status=ACTIVE`; mutable lifecycle state is enforced separately. See [Access revocation](ACCESS_REVOCATION.md).

## Phase 11 signature profile

Standardized ML-DSA-44/65/87 providers are isolated behind a byte-oriented `SignatureProvider`, with ML-DSA-65 the independent configured signing default. Version-1 canonical UTF-8 JSON FILE/SHARE payloads bind exact sender/key/version, recipient (for shares), ciphertext SHA-256, full key-envelope digest, suite/architecture, and relevant metadata. A verification failure stops before ML-KEM/X25519 recovery and AES-GCM decryption. Signatures provide sender authenticity, not confidentiality; see [Digital signatures](DIGITAL_SIGNATURES.md). Historical sections below describe earlier phase snapshots.

## Phase 10 hybrid profile

Hybrid suites combine per-envelope ephemeral X25519 agreement with suite-selected ML-KEM encapsulation. `HybridSecretCombiner` length-prefixes the 32-byte PQ and classical secrets in fixed PQ-then-classical order, and suite-selected HKDF-SHA256 derives a 32-byte KEK using a fresh salt and a versioned, authenticated context. Owner files use crypto/AAD version 4/4; hybrid shares use 3/3. AES-256-GCM content encryption is unchanged. See [Hybrid cryptography](HYBRID_CRYPTO.md) for the complete transcript, storage format, rationale, and standards references. Earlier phase profiles below are retained as historical specifications.

## Phase 9 suite composition

The approved suites are `QS-PQ-512-V1`, `QS-PQ-768-V1`, and `QS-PQ-1024-V1`. Each composes AES-256-GCM content AEAD, its named ML-KEM provider, HKDF-SHA256, and KEK-AES-256-GCM wrapping. New file KDF/wrap contexts authenticate suite ID/version and use crypto/AAD version 3/3. New share contexts use version 2/2. Exact metadata consistency is validated before cryptographic recovery, with no fallback or trial of alternate algorithms.

## Phase 7 implemented profile

Phase 7 exposes exactly three canonical choices through one byte-oriented provider contract: `LOW -> ML-KEM-512`, `STANDARD -> ML-KEM-768`, and `HIGH -> ML-KEM-1024`. The choice is explicit at upload time (or the configured `DEFAULT_SECURITY_LEVEL`) and is persisted with the exact KEM algorithm. There is no content inspection, recommendation engine, adaptive selection, or silent fallback in this phase.

`mlkem==0.1.0` supplies ML-KEM-512. `cryptography==50.0.2` supplies ML-KEM-768 and ML-KEM-1024, preserving the 64-byte private-seed representation already used by historical ML-KEM-768 records. Startup self-tests every registered provider and fails closed if any required provider is unavailable.

| Security level | Algorithm | Public key | Stored private material before protection | KEM ciphertext | Shared secret |
| --- | --- | ---: | ---: | ---: | ---: |
| `LOW` | `ML-KEM-512` | 800 bytes | 1,632 bytes | 768 bytes | 32 bytes |
| `STANDARD` | `ML-KEM-768` | 1,184 bytes | 64-byte seed | 1,088 bytes | 32 bytes |
| `HIGH` | `ML-KEM-1024` | 1,568 bytes | 64-byte seed | 1,568 bytes | 32 bytes |

Every new user receives one active key for each algorithm. Owner and share envelopes record the security level, exact KEM identifier, key ID, and key version. Decryption selects only that recorded provider and validates the level/algorithm pair; unknown, crossed, unavailable, or missing algorithms fail rather than falling back.

## Phase 8 selection boundary

`SecurityPolicyEngine` is deliberately outside the primitive/provider layer. It returns a LOW/STANDARD/HIGH decision and the existing `SecurityLevelPolicy` performs the only level-to-KEM mapping. File encryption, KEM encapsulation, HKDF-SHA256 derivation, AES-GCM wrapping, download, and sharing are otherwise unchanged.

Policy inputs and explanations are not cryptographic inputs and are not added to the existing version-2 envelope AAD in Phase 8. The selected level and exact KEM remain validated together in stored crypto metadata. Sharing uses this stored algorithm and never reruns or varies policy by recipient.

## Phase 5 historical profile

Phase 5 originally enabled only the FIPS 203 ML-KEM-768 implementation exposed by `cryptography`. Application code already depended on a byte-oriented `KEMProvider` protocol and allow-listed registry; Phase 7 extends that registry without reinterpreting historical rows.

New registrations generate a 1,184-byte public key and 64-byte private seed. The public key is stored in PostgreSQL. The private seed is AES-256-GCM protected under the application master key with AAD binding user ID, key ID, algorithm, key version, and protection version. The raw seed exists only transiently in the trusted backend.

For each version-2 upload, encapsulation to the owner's recorded public key returns a 32-byte shared secret and 1,088-byte KEM ciphertext. A fresh 32-byte salt and deterministic length-prefixed context feed HKDF-SHA256, producing a 32-byte KEK. That KEK—not the raw KEM secret—AES-GCM wraps the fresh file key. Stored metadata contains the KEM ciphertext, salt, algorithms, exact recipient key ID/version, wrapping nonce, and wrapped file key; neither shared secret nor KEK is persisted.

Version-2 download authenticates/decrypts the recorded private seed, decapsulates, derives the same KEK, authenticates/unwraps the file key, then authenticates/decrypts the entire AES-GCM object. ML-KEM implicit rejection may return different secret material for an invalid ciphertext; the downstream AES-GCM unwrap therefore provides mandatory fail-closed validation. No plaintext response is created on any failure.

## Phase 4 version-1 compatibility profile

Phase 4 implemented content encryption and temporary centralized file-key protection. These version-1 records remain explicitly supported for download, but all new uploads use the Phase 5 version-2 profile above.

For each upload, the backend allocates the file UUID first, generates a fresh 32-byte key with `AESGCM.generate_key(bit_length=256)`, and performs whole-file AES-256-GCM encryption with a fresh 12-byte nonce. The high-level library output is stored unchanged as `ciphertext || 16-byte tag`; there is no homemade chunking or detached tag. The 25 MB default limit makes authenticate-before-release practical.

The deterministic v1 content AAD is a length-prefixed binary sequence containing the domain `QuantumShield/FileContent`, crypto version, AAD version, file UUID, owner UUID, and 8-byte unsigned plaintext size. The wrapping AAD uses the same immutable values with domain `QuantumShield/FileKeyWrap`. Fixed-width UUID/version/size encodings and a 2-byte domain length prevent ambiguous concatenation.

The per-file key is wrapped using a second AES-256-GCM operation under the Base64-provisioned 32-byte application master key and an independent fresh 12-byte nonce. Its output is a 48-byte `wrapped_file_key` (`32-byte key || 16-byte tag`). Algorithms use stable IDs `AES-256-GCM` and `MASTER-AES-256-GCM`; `crypto_version=1` and `aad_version=1`. Unknown algorithms or versions fail closed.

On download, owner authorization precedes storage access. The backend reconstructs wrap AAD, authenticates/unwraps the file key, reconstructs content AAD, authenticates/decrypts the full object, and only then constructs the HTTP response. Any modified nonce, AAD-bound field, ciphertext, wrapped key, tag, or wrong master key produces a generic controlled integrity failure with no plaintext response. The retained plaintext SHA-256 is an extra exact-output check, not authentication.

## 1. Cryptographic roles

| Mechanism | Current or planned role | Not its role |
| --- | --- | --- |
| AES-256-GCM | Authenticated encryption of file content; authenticated wrapping of a 256-bit file key under a derived KEK | Public-key encryption, password hashing, or signatures |
| ML-KEM-512/768/1024 | Establish a 256-bit shared secret with a recipient public key according to FIPS 203 | Direct file encryption, identity authentication, or signatures |
| HKDF-SHA-256 | Derive a purpose- and context-bound 256-bit KEK from an ML-KEM shared secret | Password hashing or encryption |
| Argon2id (preferred) / bcrypt | Password hashing via a maintained library | General key derivation for KEM secrets |
| SHA-256 | Optional object identification, benchmark verification, fingerprints, and non-secret digests | Replacement for AES-GCM authentication |
| JWT signature/MAC | Authenticate application tokens under the selected token design | File authenticity or key encapsulation |
| ML-DSA (Phase 11) | Sender signature over canonical FILE/SHARE package metadata and ciphertext digest | File confidentiality |

AES is specified by NIST FIPS 197, GCM by NIST SP 800-38D, ML-KEM by NIST FIPS 203, and HKDF by RFC 5869. Implementation must use reviewed library APIs and recheck current standards/errata before coding.

## 2. Provider abstractions

Conceptual interfaces (not Phase 0 code):

```text
KEMProvider
  generate_keypair() -> KEMKeyPair
  encapsulate(public_key) -> {ciphertext, shared_secret}
  decapsulate(private_key, ciphertext) -> shared_secret
  algorithm_id() -> stable identifier
  security_level() -> parameter/category metadata
  validate_public_key(bytes) -> result

AEADProvider
  encrypt(key, nonce, plaintext_or_stream, aad) -> ciphertext_and_tag
  decrypt(key, nonce, ciphertext_and_tag, aad) -> plaintext_or_failure
  algorithm_id() -> stable identifier

KDFProvider
  derive(input_key_material, salt, info, output_length) -> key
  algorithm_id() -> stable identifier

SignatureProvider (Phase 11)
  generate_keypair()
  sign(private_key, message)
  verify(public_key, message, signature)
  algorithm_id()
```

Results use typed values that distinguish public keys, private keys, shared secrets, KEKs, file keys, nonces, ciphertext, and tags. The algorithm registry maps immutable identifiers such as `ML-KEM-768` and format versions to configured providers. It rejects unknown, disabled, or client-invented algorithms. Business services never import a concrete ML-KEM implementation directly.

The registry also supports a future `HybridKEMProvider` whose output is fed to a standardized/reviewed combination and KDF construction. Phase 0 deliberately does not define its own X25519 + ML-KEM combiner.

## 3. Versioned formats

The target design keeps three related formats separate:

1. **Encrypted file object:** format version, AES-GCM ciphertext and tag; the database holds nonce and immutable metadata needed to reconstruct AAD (or a reviewed framed format holds a header).
2. **File crypto metadata:** one record per encrypted file generation, identifying AES algorithm, nonce, tag length/location, object format version, immutable AAD fields, and optional ciphertext hash for operations/experiments.
3. **File key envelope:** one per authorized principal/share, holding KEM ciphertext, recipient key version, KDF salt/context version, wrapping nonce, wrapped file key plus tag, and exact algorithm identifiers.

KEM ciphertext is **not** file-global because it is created for one recipient public key. Authentication tags are normally stored with their corresponding ciphertext using the selected library/container convention; schemas record the convention/version instead of duplicating values.

Unknown versions fail closed. Existing records are never reinterpreted under a new default.

## 4. Canonical context and AAD

Serialization must be deterministic and unambiguous, using a specified canonical encoding (for example canonical CBOR) or a reviewed length-prefixed binary schema. Ordinary dictionary/JSON stringification and string concatenation are unsuitable.

Suggested immutable file AAD fields:

```text
domain = "QuantumShield/File/v1"
file_id
file_crypto_metadata_id
owner_id
content_encryption_algorithm = "AES-256-GCM"
object_format_version
plaintext_size
```

Suggested envelope KDF `info` and wrapping AAD fields:

```text
domain = "QuantumShield/FileKeyEnvelope/v1"
envelope_id
file_id
file_crypto_metadata_id
owner_id
recipient_id
recipient_crypto_key_id
kem_algorithm
kdf_algorithm
wrapping_algorithm
policy_version
security_level
purpose = "file-key-wrap"
```

The envelope identifiers must exist before wrapping (for example application-generated UUIDs). Mutable display fields, share revocation state, and filenames are not included unless made immutable and versioned. Domain labels prevent the same derived material being repurposed across protocols.

## 5. Precise encryption/upload sequence

The initial server-managed workflow is:

1. Authenticate the owner and validate account state.
2. Validate upload length, safe display filename, allowed content policy, and request metadata. Never accept a storage path.
3. Ask the `SecurityPolicyEngine` for `{security_level, kem_algorithm, policy_version, reason_codes}`. Apply organization/system minimums and ensure the algorithm is enabled.
4. Resolve the owner's active compatible ML-KEM public-key record for the owner envelope; generate one through the key lifecycle flow if policy permits and none exists.
5. Allocate immutable `file_id`, crypto-metadata ID, object ID, and owner-envelope ID before cryptographic operations so they can be bound into AAD.
6. Generate a fresh 32-byte (256-bit) AES file key using the operating-system CSPRNG.
7. Generate a fresh 12-byte (96-bit) file nonce using the CSPRNG. This nonce may be public but must not repeat under the same key.
8. Canonically encode file AAD and encrypt the complete file with AES-256-GCM. Preserve the authentication tag according to the versioned object format.
9. Use the selected KEM provider to encapsulate to the owner's public key, producing `kem_ciphertext` and a transient `shared_secret`.
10. Generate a non-secret random KDF salt, construct canonical `info`, and derive exactly 32 bytes of KEK with HKDF-SHA-256.
11. Generate a fresh 12-byte wrapping nonce and encrypt the 32-byte AES file key with AES-256-GCM under the KEK using canonical envelope AAD. This produces the wrapped key and its tag.
12. Persist the encrypted file through `StorageService` and persist file metadata plus the owner envelope using a recoverable upload state machine. Never persist the plaintext, file key, shared secret, or KEK.
13. Best-effort erase mutable buffers holding the file key, shared secret, KEK, private material, and plaintext as soon as no longer needed; avoid copies. Python/runtime limitations mean erasure cannot be guaranteed.
14. Emit a redacted audit event with actor, file ID, selected algorithms, policy/reason, outcome, and correlation ID.
15. Return a file resource without storage paths, secrets, KEM shared secret, wrapped-key plaintext, or sensitive internal errors.

For initial manageable file limits, an implementation may authenticate an entire buffered temporary ciphertext before commitment. A later large-file implementation must choose a reviewed authenticated streaming/framing construction. Simply emitting ordinary AES-GCM plaintext chunks before final tag verification is prohibited.

## 6. Add-recipient sequence

1. Authenticate the caller; verify the caller owns the active file.
2. Validate the recipient and prevent invalid/self/duplicate grants according to product policy.
3. Resolve the recipient's active public key for the selected algorithm. The envelope records the exact key record and fingerprint.
4. Recover the AES file key through the owner's valid envelope: unwrap the owner's private key, decapsulate, derive the owner-envelope KEK, and authenticate/unwrap the file key.
5. Encapsulate independently to the recipient public key, yielding a new KEM ciphertext and shared secret.
6. Derive a new recipient-specific KEK using a fresh salt and recipient-envelope context.
7. Wrap the same AES file key using a fresh wrapping nonce and recipient-envelope AAD.
8. Atomically create the share and envelope, then discard all transient secrets as far as practical.

The file ciphertext is not regenerated. A provider/algorithm migration that changes the file-encryption format is a different operation from adding a share.

## 7. Precise decryption/download sequence

1. Authenticate the caller and resolve the requested file without leaking other users' resource existence.
2. Authorize the caller as owner or an active, non-revoked recipient.
3. Load exactly the caller's active envelope and referenced user key version; reject mismatched recipient/file/key references.
4. Load/decrypt the server-managed ML-KEM private-key blob using the external server KEK and private-key-record AAD.
5. Select the exact recorded KEM provider and decapsulate the recorded KEM ciphertext.
6. Reconstruct canonical KDF `info`; derive the same KEK using the recorded salt and HKDF-SHA-256.
7. Reconstruct envelope AAD and authenticate/decrypt the wrapped file key. Treat any mismatch as failure. Do not distinguish wrong-key, tamper, or tag failure to the requester.
8. Fetch the exact encrypted storage object and reconstruct immutable file AAD.
9. Authenticate/decrypt using AES-256-GCM. Release or commit plaintext only if tag verification succeeds completely.
10. Recheck authorization/revocation immediately before release where the implementation's transaction/stream model permits.
11. Return the original bytes with a safely encoded display filename and approved content type. Discard transient private key, shared secret, KEK, and file key buffers where practical.
12. Record a redacted success/failure audit event.

### Mandatory failure behavior

- **Wrong private key:** derived material will not authenticate the wrapped key; return generic decryption failure, no file key/plaintext.
- **Tampered KEM ciphertext/envelope:** unwrap authentication fails; return generic failure.
- **Tampered file ciphertext/nonce/AAD or invalid tag:** return no plaintext and a generic integrity/decryption failure.
- **Revoked access:** deny before secret processing when possible, and never return required metadata/material afterward.
- **Missing metadata, unknown version, or disabled algorithm:** fail closed; never infer or downgrade.

## 8. Multi-recipient and rotation behavior

Each recipient receives an independent envelope. Deleting/revoking one envelope does not alter the file object or other envelopes. User ML-KEM rotation creates a new key record; new shares use it, while old private-key versions remain protected and available only as long as valid historical envelopes reference them. Optional rewrapping migrates an envelope to a new recipient key without re-encrypting the file.

File-key rotation requires decrypting and re-encrypting the file with a new key and nonce, then recreating all active envelopes. It is materially more expensive and is not implied by user-key rotation or revocation.

## 9. Integrity and optional SHA-256

AES-GCM authentication is authoritative for encrypted content. SHA-256 may record a ciphertext/object digest to detect wrong-object retrieval or support benchmark verification and may fingerprint public keys. A plaintext digest can reveal equality and aid guessing for predictable files; it should not be persisted by default. Deduplication is a separate privacy/security decision and is not part of the initial design.

## 10. Digital signatures (Phase 11 implemented; historical planning text follows)

Phase 11 canonical FILE/SHARE payloads include file crypto metadata digest, ciphertext digest, sender/owner identity, signing key/version, policy decision, and recipient-bound share envelope digest. A server-held ML-DSA key signs the payload; recipients verify against the exact recorded sender signing-key binding before decryption. Signatures add sender authenticity but do not replace AES-GCM or authorization. Rotation, revocation, and replay/rollback prevention remain outside this phase; see [Digital signatures](DIGITAL_SIGNATURES.md).

## 11. Algorithm-selection guardrails

- The backend, not the request, makes the final selection from an allow-list.
- User choice may request a stronger level; it cannot bypass configured minimums.
- Provider availability failure causes a closed failure, not a silent weaker fallback.
- Algorithm and format identifiers are stable values, not Python class names or library-specific aliases.
- Policy selection is logged with version and reason codes.
- ML-KEM parameter-set comparisons acknowledge that larger sets trade greater claimed security strength for key/ciphertext size and performance; selection is a policy experiment, not a new primitive.

## 12. Test strategy for later phases

- Official ML-KEM known-answer/validation vectors supported by the chosen provider.
- AES-GCM and HKDF published vectors.
- Round-trip tests for every supported version and parameter set.
- One-bit tampering of ciphertext, tags, nonces, AAD, KEM ciphertext, wrapped key, recipient/key IDs, algorithms, and versions.
- Wrong-recipient and wrong-private-key tests.
- Nonce length/uniqueness and file-key non-reuse tests with injectable deterministic test RNG only in tests.
- Serialization stability/canonicalization tests across processes and versions.
- Provider registry unknown/disabled/downgrade tests.
- No-partial-plaintext tests, including interrupted/large downloads.
- Secret-redaction tests for exceptions, logs, traces, and benchmark records.

## 13. References

- [NIST FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D — Galois/Counter Mode](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/info/rfc5869/)

## 14. Phase 6 recipient envelope profile

Phase 6 does not change the content format. It recovers the existing 32-byte file key from the owner envelope and, for each recipient, performs a fresh ML-KEM-768 encapsulation, fresh 32-byte HKDF-SHA256 salt, and fresh AES-256-GCM key-wrap nonce. The resulting recipient KEM ciphertext, salt, wrapped file key, nonce, algorithm identifiers, exact key ID/version, and format versions are stored. The ML-KEM shared secret, derived KEK, and plaintext file key are never persisted.

Share derivation and wrapping use separate domains:

- `QuantumShield/FileShareKeyDerivation/v1`
- `QuantumShield/FileShareKeyWrap/v1`

Both encode length-prefixed domains and fixed-width binary fields for share ID, file ID, owner ID, recipient ID, recipient key ID/version, canonical KEM algorithm, plaintext size, crypto version, and AAD version. This prevents envelope substitution between users, files, shares, or key versions. Wrong-recipient decapsulation may yield pseudorandom material, but AES-GCM key-wrap authentication then fails and releases no file key.

The server minimizes application references to recovered file/private keys after use, but Python immutable buffers and underlying library copies cannot be guaranteed zeroized.

