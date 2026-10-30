# Phase 9 crypto-agile boundary

This package exposes separate AEAD, KEM, KDF, and key-wrap provider contracts,
strict provider registries, approved versioned crypto suites, explicit version
dispatch, and AES-256-GCM content encryption with standardized
ML-KEM-512/768/1024 encapsulation/decapsulation through one provider protocol,
HKDF-SHA256 KEK derivation, version-2 file-key protection, recipient-bound share
envelopes, and master-key protection for server-managed private keys.
The Phase 4 version-1 and Phase 5-8 version-2 paths remain for compatibility;
new suite-bound files use version 3.

Share KDF/wrap context binds the share, file, owner, recipient, exact key ID/version,
algorithm, plaintext size, and format versions with deterministic length-prefixing.
The separate `SecurityPolicyEngine` selects a level; this package validates and
maps that level without knowing sensitivity/category rules. It does not inspect
files. This package does not implement rotation, signatures, hybrid cryptography,
revocation, or benchmarking.
