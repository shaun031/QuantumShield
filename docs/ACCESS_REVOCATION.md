# Phase 12 access revocation and share lifecycle

## Guarantee and limit

QuantumShield revocation stops **future downloads through the application**. It does not erase plaintext, the file AES key, ciphertext, or sufficient decryption material that a recipient obtained before revocation. This is application-level grant invalidation, not retroactive cryptographic erasure. The encrypted file is not re-encrypted when one recipient is revoked.

```text
One AES-256-GCM encrypted file
  ├─ owner's file-key envelope: remains usable
  └─ Bob's independent share envelope
       ACTIVE -> Bob may download
         |
         Alice revokes
         v
       REVOKED + recipient envelope inactive -> future Bob downloads rejected
```

Each `FileShare` has `ACTIVE` or `REVOKED` status. Revocation records `revoked_at`, `revoked_by_user_id`, and an optional 255-character reason. `ShareCryptoMetadata.is_active` disables the recipient's key-access package without deleting historical cryptographic metadata. Migration `0011_share_revocation` backfills existing shares/envelopes to active, replaces the old unique file/recipient constraint with a partial **one active share** index, and adds a secret-free `audit_logs` table. Old revoked rows and their signatures remain visible to sender and recipient.

## API and transactions

Authenticated `POST /api/shares/{share_id}/revoke` accepts optional JSON `{"reason":"..."}`. Only the file owner/sender can revoke; unrelated users and recipients receive the same 404 as an unknown share. An already revoked grant returns its existing revoked state without creating another transition. A conditional `ACTIVE -> REVOKED` database update serializes competing revocations; the same transaction disables its recipient envelope and inserts one `SHARE_REVOKED` event. The audit table has a unique revocation-event index per share. A failure rolls back all three changes.

Received and sent list/detail endpoints include both active and revoked history, with `status` and `revoked_at`. The recipient's download endpoint obtains the share with a PostgreSQL shared row lock, checks status and the revocation audit marker **before** signature verification, private-key recovery, KEM decapsulation, HKDF, or AES decryption, and returns safe 403 on revoked access. It also rejects an inactive/mismatched recipient envelope even if the share status says active. A denied revoked download attempts to append `SHARE_DOWNLOAD_DENIED_REVOKED`; audit-write failure never allows plaintext through. PostgreSQL locks make an in-progress download and revocation serialize at the grant check; they cannot retract plaintext already delivered.

Creating a new share after revocation produces a new `FileShare` ID, fresh KEM ciphertext, HKDF salt, key-wrap nonce, and (for HYBRID) ephemeral X25519 public key, plus a new ML-DSA SHARE signature and `SHARE_CREATED` event. It never reactivates an old envelope. The old share remains `REVOKED`. Revocation does not rerun adaptive selection or alter the file's stored suite/ciphertext.

Phase 11 SHARE payload version 1 contains the **creation snapshot** `status=ACTIVE`; Phase 12's mutable lifecycle state is checked separately. This preserves historical signature verification after revocation. No new audit-event signature or tamper-evident log chain is claimed. A privileged database attacker who removes the revocation event and restores both share and envelope state may bypass application controls; external anchoring and hardened database privileges are future work. Normal download also checks the retained revocation event, so changing just the status/envelope fields does not restore access.

Owner file deletion remains distinct: it removes the live ciphertext and cascades all dependent shares/envelopes/signatures, while retaining a `FILE_DELETED` audit event. One-recipient revocation retains the file and every other recipient's access. Neither action can delete copies already held by recipients or backups.

## Threats and UI

The UI shows revoked shares in both sent and received history. Received revoked rows have no usable download button; sent active rows have a Revoke Access button. The owner sees this confirmation: “Revocation prevents future downloads through QuantumShield. It cannot remove files already downloaded by the recipient.” Direct API calls enforce the same rule even if a browser button is bypassed. A guessed old share ID remains useless to an unrelated user, and an authorized former recipient receives a safe revoked response without key material.

`audit_logs` records event type, actor, file/share/recipient IDs, old/new state, reason where applicable, and timestamp. It never records keys, wrapped keys, filenames, plaintext, or signature private material. Events implemented here are `SHARE_CREATED`, `SHARE_REVOKED`, `SHARE_DOWNLOAD_DENIED_REVOKED`, and `FILE_DELETED`. This is a normal database audit trail, not cryptographically tamper-evident logging.

Windows checks from `D:\Data Security Project\backend` after configuring `.env` and PostgreSQL:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts\check_crypto.py
```

Phase 13 benchmarking is separate from, and does not change, this Phase 12 revocation guarantee.
