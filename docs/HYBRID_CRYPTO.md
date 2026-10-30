# Phase 10 hybrid key establishment

QuantumShield offers `PQ_ONLY` (default) and explicitly selected `HYBRID` key establishment. The Phase 8 policy still selects only LOW/STANDARD/HIGH. A trusted mapping of `(architecture, level)` chooses one of six approved suites; clients never supply arbitrary provider combinations. Existing PQ-only files and shares keep their stored suite and format.

## Construction and rationale

```text
Recipient X25519 public key             Recipient ML-KEM public key
             |                                      |
  fresh ephemeral X25519 private key       ML-KEM encapsulation
             |                                      |
   32-byte classical secret                32-byte PQ secret
             \                                      /
              length-prefixed PQ || classical input
                            |
     HKDF-SHA256, fresh 32-byte salt, suite-bound info
                            |
                        32-byte KEK
                            |
              AES-256-GCM wraps file AES key

File plaintext -- fresh file AES key + AES-256-GCM --> one ciphertext
```

The combiner uses the fixed order **ML-KEM secret, then X25519 secret**, each with a two-byte big-endian length prefix, as HKDF input keying material. This is a project-specific storage-envelope construction informed by [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html), [RFC 10024](https://datatracker.ietf.org/doc/rfc10024/), and [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869/). It is **not** an implementation of TLS `X25519MLKEM768`, and TLS transcript security cannot be assumed here. QuantumShield instead binds the file/share role, IDs, exact recipient key IDs/versions, security level, suite ID/version, architecture, algorithm, format versions, plaintext size, ephemeral and recipient X25519 public keys into its project-specific HKDF info and a separately domain-labeled AES-GCM wrapping AAD. The role is `OWNER` or `SHARE`; a share additionally binds its share ID. Unknown versions or inconsistent identifiers fail closed.

The X25519 public and private serialization is 32 raw bytes each. One X25519 user keypair is reused across all hybrid levels; its private bytes are protected by the existing master-key AES-256-GCM service under user/key/algorithm/version-bound AAD. A fresh sender ephemeral keypair is generated per owner or recipient wrap. Its **public** half is stored; its private half, both component secrets, combined input, and derived KEK are never persisted. Python cannot guarantee in-memory zeroization.

The HKDF salt is 32 fresh random bytes per envelope. The key-wrap nonce is a separate 12-byte random value. Content encryption has its own fresh file key and nonce. AES-GCM authentication must succeed before any plaintext is returned. Invalid X25519 public keys/low-order results, wrong private keys, changed KEM ciphertext, salt, suite, context, or wrapped key cause recovery failure. A working component cannot trigger fallback to PQ-only or a lower level.

| Architecture | LOW | STANDARD | HIGH |
| --- | --- | --- | --- |
| `PQ_ONLY` | `QS-PQ-512-V1` | `QS-PQ-768-V1` | `QS-PQ-1024-V1` |
| `HYBRID` | `QS-HYBRID-512-V1` | `QS-HYBRID-768-V1` | `QS-HYBRID-1024-V1` |

Hybrid files use crypto/AAD version **4/4**; hybrid shares use **3/3**. Both store `security_architecture`, suite ID/version, exact ML-KEM key ID/version, exact X25519 key ID/version, `classical_algorithm=X25519`, 32-byte ephemeral public key, ML-KEM ciphertext, 32-byte HKDF salt, `combiner_version=1`, and the AES-GCM-wrapped file key/nonce. File content stays AES-256-GCM and is stored once regardless of share count. Phase 4 files use 1/1; historical ML-KEM files use 2/2; Phase 9 PQ suite files use 3/3. PQ shares retain 1/1 or 2/2. The version dispatcher does not reinterpret those bytes.

Registration provisions three ML-KEM keys plus one X25519 key atomically. Existing users can run `python scripts\provision_hybrid_keys.py` or call `POST /api/crypto/keys/ensure`; both are idempotent and create only missing active algorithms. Missing recipient X25519 or exact ML-KEM key causes a safe conflict, never downgrade. `0009_hybrid_envelopes` adds the allow-list and hybrid columns/constraints, leaving historical rows `PQ_ONLY`; downgrade refuses if hybrid or X25519 records exist.

Hybrid adds transitional diversity: X25519 is widely deployed classical key agreement, while ML-KEM is the post-quantum component. It does not add security levels numerically, does not make X25519 quantum-resistant, and does not protect against a compromised trusted backend/master key or authorized recipient copying plaintext. Metadata and access patterns remain visible to the backend/database. ML-KEM-512 still uses a beta dependency and needs production review. The combiner and full application need independent cryptographic review before production claims.
