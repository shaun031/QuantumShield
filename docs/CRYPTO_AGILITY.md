# Crypto Agility

## Phase 11 signature agility

Signing profiles `QS-SIG-MLDSA44-V1`, `QS-SIG-MLDSA65-V1`, and `QS-SIG-MLDSA87-V1` are separate from confidentiality suites. The configured active signing algorithm is ML-DSA-65 by default, independent of ML-KEM level and optional hybrid mode. Verification dispatches by the stored profile and exact signing key ID/version; unknown or disabled profiles fail closed. There is no opportunistic downgrade to unsigned for new records. See [Digital signatures](DIGITAL_SIGNATURES.md).

## Phase 10 extension

The suite registry now maps `(PQ_ONLY|HYBRID, LOW|STANDARD|HIGH)` to six allow-listed suites. A separate `KeyAgreementProvider` supplies X25519 while ML-KEM retains its KEM semantics. `HybridKeyProtector` composes both, and `HybridSecretCombiner` derives a suite/context-bound KEK with HKDF-SHA256. The explicit file dispatcher adds hybrid crypto/AAD 4/4; hybrid shares use 3/3. Earlier versions and PQ-only suites remain unchanged. See [Hybrid cryptography](HYBRID_CRYPTO.md).

Phase 9 makes algorithms replaceable behind explicit cryptographic roles without allowing users to assemble arbitrary combinations. Crypto agility here means controlled provider substitution and versioned historical dispatch—not automatic fallback, algorithm guessing, or weaker runtime choices.

## Trust boundary and flow

```text
Security Policy Engine
        |
        v
Security Level + trusted Suite ID
        |
        v
Crypto Suite Registry
        |
        v
Crypto Suite / orchestration
   +---------+---------+---------+----------+
   |         |         |         |          |
   v         v         v         v          |
  AEAD      KEM       KDF     KeyWrap       |
   |         |         |         |          |
AES-GCM   ML-KEM   HKDF-SHA256 AES-GCM      |
   +---------+---------+---------+----------+
```

`FileService` and `ShareService` consume policy decisions, stored suite identifiers, and orchestration services. They do not import `AESGCM`, `HKDF`, or native ML-KEM libraries.

## Approved suites

| Security level | Suite ID | AEAD | KEM | KDF | Key wrap |
|---|---|---|---|---|---|
| LOW | `QS-PQ-512-V1` | AES-256-GCM | ML-KEM-512 | HKDF-SHA256 | KEK-AES-256-GCM |
| STANDARD | `QS-PQ-768-V1` | AES-256-GCM | ML-KEM-768 | HKDF-SHA256 | KEK-AES-256-GCM |
| HIGH | `QS-PQ-1024-V1` | AES-256-GCM | ML-KEM-1024 | HKDF-SHA256 | KEK-AES-256-GCM |
| LOW | `QS-HYBRID-512-V1` | AES-256-GCM | X25519 + ML-KEM-512 | HKDF-SHA256 | KEK-AES-256-GCM |
| STANDARD | `QS-HYBRID-768-V1` | AES-256-GCM | X25519 + ML-KEM-768 | HKDF-SHA256 | KEK-AES-256-GCM |
| HIGH | `QS-HYBRID-1024-V1` | AES-256-GCM | X25519 + ML-KEM-1024 | HKDF-SHA256 | KEK-AES-256-GCM |

The suite specification is the single security-level mapping source. API clients choose a security level, never provider classes or an arbitrary suite. Registry lookups reject unknown or disabled IDs. ACTIVE suites can encrypt and decrypt; DEPRECATED suites can only decrypt; DISABLED suites fail closed.

## Providers and registration

The crypto boundary defines separate `AEADProvider`, `KEMProvider`, `KDFProvider`, and `KeyWrapProvider` contracts. `AES256GCMProvider`, the three ML-KEM providers, `HKDFSHA256Provider`, and `AESGCMKeyWrapProvider` implement them. Startup composes allow-listed provider registries into `CryptoSuiteRegistry` and runs each unique provider self-test.

Provider-native names and library details remain inside the ML-KEM implementations. Stored and API-facing names use canonical application identifiers from `app/crypto/identifiers.py`.

## Stored versions and historical decryption

File and share crypto rows store `crypto_suite_id` and `crypto_suite_version` alongside explicit algorithms for audit and consistency validation. Migration `0008_crypto_suites` backfills unambiguous Phase 5–8 records from their stored ML-KEM identifier without changing `crypto_version`.

File dispatch is explicit:

- crypto/AAD version 1/1: legacy Phase 4 master-key envelope;
- version 2/2: legacy ML-KEM envelope, validated against the backfilled suite;
- version 3/3: Phase 9 suite-bound envelope.

Share version 1/1 remains readable; new suite-bound shares use version 2/2. Stored versions and suite IDs control decryption. Current defaults and policy are never used to reinterpret historical ciphertext.

Suite ID, suite version, security level, content algorithm, KEM, KDF, and key-wrap identifiers must match the registry exactly. The suite identity and version are also authenticated in new KDF/wrapping contexts. Unknown suites, mismatched recipient keys, and inconsistent algorithm metadata are rejected without fallback.

## Adding a future approved algorithm

To add a new KEM later:

1. Implement `KEMProvider` and isolate any library-name compatibility mapping there.
2. Register the provider in the allow-listed KEM factory.
3. Define a trusted suite specification and lifecycle status.
4. Add a database migration for the new suite identifier and its metadata constraints.
5. Add provider, confusion, suite integration, upload, sharing, and historical-format tests.

Phase 10 adds a distinct hybrid orchestration branch in `FileService` and `ShareService` because X25519 is key agreement, not a KEM. The Phase 9 provider/suite registry and version dispatcher remain authoritative. Signatures were added in Phase 11, Phase 12 adds application-level share revocation, and Phase 13 measures the existing providers through an offline harness. The X25519-only baseline remains benchmark-only.
