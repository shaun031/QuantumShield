# Phase 11 digital signatures and sender authenticity

## Security boundary

The trusted backend signs every newly uploaded file and every newly created share with the sender/owner's ML-DSA signing identity. AES-256-GCM still encrypts content. ML-KEM establishes a post-quantum shared secret; optional X25519 contributes a classical secret in hybrid mode; HKDF-SHA256 derives the wrapping KEK. ML-DSA is **only** for sender authenticity and signed metadata integrity. It never encrypts or replaces those primitives.

```
Alice's protected ML-DSA private seed
    -> canonical FILE or SHARE payload + actual ciphertext digest
    -> ML-DSA signature stored with metadata
Bob's authorized share lookup
    -> exact recorded Alice signing public key and version
    -> rebuild canonical payload from current metadata and actual ciphertext
    -> VALID: recover recipient envelope key, decrypt, deliver
    -> INVALID: reject before key recovery and decryption
```

The signing provider wraps the maintained [`cryptography==50.0.2` ML-DSA API](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/mldsa/). Profiles `QS-SIG-MLDSA44-V1`, `QS-SIG-MLDSA65-V1`, and `QS-SIG-MLDSA87-V1` are separate from confidentiality suites. `DEFAULT_SIGNATURE_ALGORITHM=ML-DSA-65` selects the active signing identity and does **not** follow LOW/STANDARD/HIGH ML-KEM levels. No request parameter chooses an arbitrary signing algorithm. The registry runs key-generation/sign/verify/tamper self-tests at startup. Stored profile ID and key version select historical verification, not the current signing default.

## Key custody

Registration creates one active ML-DSA-65 signing key in addition to three ML-KEM keys and X25519. `user_crypto_keys.key_purpose` is `SIGNATURE`, `KEM`, or `KEY_AGREEMENT`; database checks reject algorithm-purpose mismatch. ML-DSA stores the 32-byte FIPS 204 seed encrypted under the existing master-key AES-256-GCM service (48-byte ciphertext/tag plus 12-byte nonce). Public keys are 1,312/1,952/2,592 bytes for ML-DSA-44/65/87. Private material is never returned by APIs, printed by diagnostics, or used as a KEM key. The exact signing key ID and version stay attached to each signature so an inactive but retained historical key can still verify. No rotation or revocation workflow is introduced.

For existing users, run `python scripts/provision_signing_keys.py` after `alembic upgrade head`; it creates only missing signing keys. `POST /api/crypto/keys/ensure` also idempotently ensures the full five-key set. Existing file and share records are **not** retroactively signed.

## Canonical payload and storage

Payload version 1 is sorted-key UTF-8 JSON with no insignificant whitespace and UTC timestamps normalized to microsecond ISO-8601 `Z`. Binary metadata in key packages is standard Base64. The same builder is used for signing and verification. Every immutable persisted owner/recipient cryptographic-envelope field is included in a SHA-256 key-package digest; Phase 12's mutable `is_active` authorization state is excluded and checked separately. FILE signs scope, file/owner/sender IDs, exact signing key ID/version, signature algorithm/profile, timestamp, filename, MIME, size, plaintext SHA-256, **actual ciphertext SHA-256**, owner key-package digest, suite/security/architecture/version, and adaptive policy metadata. SHARE signs scope, share/file/owner/sender/recipient IDs, exact signing key ID/version, timestamp, permission/creation status (`ACTIVE`), ciphertext SHA-256, recipient key-package digest, owner key-package digest, and suite/security/architecture/version. A SHARE signature can be valid for a legacy-unsigned FILE; it still binds that file's current owner envelope and ciphertext. Phase 12 revocation does not rewrite that signed creation snapshot.

`digital_signatures` stores FILE/SHARE scope, signer user, exact key ID/version, profile/algorithm/payload version, signature bytes, ciphertext digest, key-package digest, and relationship IDs. Unique partial indexes allow one FILE signature per file and one SHARE signature per share. The `files.signature_required` and `file_shares.signature_required` flags are false for pre-migration rows and true for newly signed rows. A required missing signature is INVALID; old unsigned rows explicitly report `LEGACY_UNSIGNED` and retain their historical decryption path. If a signature row is present, it must verify even when the legacy flag is false. Signature validity is **never** cached as a trusted database boolean.

Uploads write the one ciphertext object, flush file metadata, sign, and commit atomically with respect to the database; a signing failure rolls back metadata and removes the ciphertext. Share creation validates the FILE signature, creates the recipient envelope, signs the SHARE metadata, and commits together. Owner and recipient downloads read the ciphertext once and verify signatures over those exact bytes **before** key recovery/decryption. Owner download requires FILE verification; recipient download requires both FILE and SHARE verification when present/required. Read-only `GET /api/files/{id}/verify` and `GET /api/shares/{id}/verify` return `VALID`, `INVALID`, or `LEGACY_UNSIGNED`, plus safe signer/algorithm metadata for valid signatures. Downloads enforce verification independently of the UI. Signature errors return safe `422` messages; no raw keys/signatures or decrypted data leak.

## Threats, limitations, and operations

Signatures detect ciphertext replacement, recipient substitution, signer-key substitution, and changes to signed metadata/envelopes. They do **not** grant access; owner/recipient authorization remains mandatory. They do not hide metadata, prevent replay of a complete old valid package, prevent database rollback, revoke prior downloads, or protect against a compromised backend/master key/signing private key. The server is the signer; this is not client-held non-repudiation. A privileged attacker able to change both database flags and signature rows can downgrade a new record to appear legacy-unsigned; external audit anchoring/immutable provenance is outside Phase 11. Keep backups and access controls accordingly. ML-DSA adoption and the complete composition require independent production security review.

Windows checks from `backend`:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe scripts\provision_signing_keys.py
.\.venv\Scripts\python.exe scripts\check_crypto.py
.\.venv\Scripts\python.exe -m pytest -q
```

Set up `.env` and PostgreSQL first; the provisioning command uses the deployment `MASTER_KEY_BASE64` and must retain the same master key used for existing protected user keys. Phase 12 revocation, benchmarking, and blockchain are not part of this phase.
