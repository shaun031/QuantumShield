# QuantumShield Backend

Phase 14 adds a paired, offline Adaptive-versus-Fixed-HIGH experiment using the unchanged Phase 8 policy and Phase 13 providers. Phase 12 owner-only share revocation and Phase 11 ML-DSA signatures remain intact. See [adaptive evaluation](../docs/ADAPTIVE_EVALUATION.md), [benchmarking](../docs/BENCHMARKING.md), and [access revocation](../docs/ACCESS_REVOCATION.md).

## Adaptive policy API

- `GET /api/security/options` returns modes, sensitivities, categories, ranked levels, mappings, and policy version.
- `POST /api/security/recommend` evaluates metadata without uploading file contents.
- `POST /api/files/upload` accepts `selection_mode`, optional `security_level`, `sensitivity`, and `document_category`.
- `GET /api/files/{id}/security-decision` returns the full stored explanation to the owner only.

Policy `adaptive-v1` is deterministic. Rules contribute minimum levels and the strongest wins. RECOMMEND may be increased but not reduced below the policy minimum; AUTO rejects an explicit level. Sharing never reruns policy and continues to use the stored file algorithm.

## Offline adaptive evaluation

After a Phase 13 standard run, execute `python scripts\run_adaptive_experiment.py --profile quick` or `--profile standard` from this directory. No database or `.env` is required. The CLI validates the latest Phase 13 standard export, runs paired PQ-only and hybrid workloads, and writes `benchmark_results\adaptive\<run_id>\` CSV/JSON artifacts. The frontend `/benchmarks` page can load the completed `adaptive_vs_fixed.json` locally. See [adaptive evaluation](../docs/ADAPTIVE_EVALUATION.md) for methodology and limitations.

## Windows installation

Windows Command Prompt instructions and the missing-local-`.env` repair are in [Windows configuration](../docs/WINDOWS_CONFIGURATION.md). Configuration loads `backend/.env` from an absolute backend-relative path. Keep existing secrets and set the PostgreSQL password locally; a fresh master key cannot decrypt an older dataset.

`mlkem==0.1.0` supplies ML-KEM-512; `cryptography==50.0.2` supplies AES-GCM, ML-KEM-768/1024, and standardized ML-DSA-44/65/87. Both are pinned Windows wheels. The provider registries self-test their algorithms and fail startup instead of downgrading.

```powershell
cd "D:\Data Security Project\backend"
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
if (-not (Test-Path .env)) { python scripts\init_dev_env.py }
```

Configure `SECRET_KEY`, `DATABASE_URL`, and the Base64 encoding of exactly 32 random bytes as `MASTER_KEY_BASE64`. Keep:

```dotenv
DEFAULT_SECURITY_LEVEL=STANDARD
DEFAULT_SIGNATURE_ALGORITHM=ML-DSA-65
```

Startup performs an ML-KEM generation/encapsulation/decapsulation self-test and fails rather than selecting another algorithm.

## User keys

Registration provisions three ML-KEM keys, one X25519 key, and one ML-DSA-65 signing key in one transaction. Existing users call `POST /api/crypto/keys/ensure` for the full keyset or `python scripts\provision_signing_keys.py` for signing only; both create only missing algorithms. `GET /api/crypto/keys/me` returns the active keyset, and KEM public-key lookup accepts an exact `algorithm` query. `GET /api/crypto/signing-key/{user_id}` returns only the active signing public key.

All private key material is AES-256-GCM encrypted. Private-key AAD binds user ID, key ID, canonical algorithm, key version, and protection version. APIs never return secret key material.

## File format versions

- Version 1: Phase 4 AES-256-GCM content plus master-key-wrapped file key.
- Version 2: AES-256-GCM content plus the stored selected ML-KEM algorithm, HKDF-SHA256, and an AES-GCM-wrapped file key.
- Version 3: suite-bound content and owner envelope with authenticated suite ID/version and exact provider identifiers.
- Version 4: hybrid X25519 + ML-KEM owner envelope, with crypto/AAD 4/4 and a fresh ephemeral X25519 public key. Hybrid shares use 3/3; PQ-only shares retain 1/1 or 2/2.

Version 2 uses fresh content/wrapping nonces and a fresh 32-byte HKDF salt. KDF info and wrapping AAD bind file ID, owner ID, recipient key ID/version, KEM algorithm, crypto/AAD versions, and plaintext size through deterministic length-prefixed binary encoding.

## Migrations and verification

```powershell
alembic upgrade head
python -m pytest
python -m compileall -q app tests scripts
python -m pip check
python -m scripts.check_pqc
python -m scripts.check_crypto
python -m scripts.check_hybrid
python scripts\provision_hybrid_keys.py
python scripts\provision_signing_keys.py
uvicorn app.main:app --reload
```

Migration chain:

- `0001_create_users`
- `0002_create_files`
- `0003_file_crypto`
- `0004_mlkem_keys`
- `0005_secure_sharing`
- `0006_multi_mlkem`
- `0007_adaptive_policy`
- `0008_crypto_suites`
- `0009_hybrid_envelopes`
- `0010_digital_signatures`
- `0011_share_revocation`

`0004` adds `user_crypto_keys` plus optional KEM/KDF/recipient-key fields to `file_crypto_metadata`. Existing version-1 rows remain valid.

`0005` adds `file_shares` and `share_crypto_metadata`, including ownership/recipient foreign keys, one envelope per share, an initial unique file/recipient relationship, context/version checks, indexes, and cascade cleanup from file deletion. Phase 12 replaces that uniqueness rule with one active grant per file/recipient so revoked history can coexist with a new grant. The original migration supports downgrade and does not alter Phase 5 file rows.

`0006` adds security levels, expands algorithm/size constraints for all three parameter sets, and backfills known Phase 5/6 ML-KEM-768 file/share rows to `STANDARD`. Upgrade, downgrade, and re-upgrade are supported.

`0007` adds nullable selection mode, sensitivity, category, recommendation, policy version, JSON reasons/rules, and override fields. Historical rows are deliberately left null and their stored KEM metadata is not reclassified. New application uploads record a complete decision.

`0008` adds suite ID/version to file and share metadata, backfills unambiguous ML-KEM rows, preserves their crypto versions, and adds suite/algorithm consistency constraints. New files use crypto/AAD version 3/3; new shares use 2/2. `GET /api/crypto/suites` exposes only safe allow-listed capability metadata.

`0009` permits encrypted X25519 user keys, adds architecture and hybrid-envelope metadata, registers hybrid suite constraints, and leaves old rows PQ-only. It refuses downgrade while X25519/hybrid records remain.

`0010` adds purpose-separated encrypted ML-DSA keys, FILE/SHARE signature rows, and legacy-aware required-signature flags. Run the idempotent signing-key provisioning script for existing users. It refuses downgrade while signed rows or signing keys remain.

`0011` adds revoked-share timestamps/actor/reason, recipient-envelope active state, a partial unique index for one active file/recipient grant, and secret-free audit events. Existing shares stay active. It refuses downgrade while revocation history exists.

## Sharing API

- `GET /api/users/search?q=...` requires authentication, at least three non-space characters, and returns at most 20 safe user records.
- `POST /api/files/{file_id}/share` derives the sender from the JWT, verifies ownership, and creates an atomic recipient envelope without touching storage.
- `GET /api/shares/received`, `GET /api/shares/sent`, and `GET /api/shares/{id}` return allow-listed metadata.
- `GET /api/shares/{id}/download` is recipient-only and uses the exact recorded recipient key ID/version.
- `POST /api/shares/{id}/revoke` is owner-only and idempotently disables future application downloads for that recipient; sent and received views retain revoked history.

Self-sharing returns `400`; missing recipient keys and duplicate active shares return `409`; inaccessible resources return `404`; authenticated cryptographic failures return safe `422` responses.

## Limitations

This is trusted-server key custody, not zero-knowledge. Python cannot guarantee zeroization. Adaptive classification relies on user-supplied metadata and project-defined rules; there is no content inspection or ML model. The ML-KEM-512 provider is beta and needs production reassessment. Hybrid and signature composition need independent cryptographic review. There is no key rotation or KMS/HSM integration. Offline synthetic benchmarks are available through `python scripts\run_benchmarks.py --profile quick`; see [benchmarking](../docs/BENCHMARKING.md). Revocation cannot retract already downloaded plaintext or keys. Existing unsigned records remain explicitly legacy-unsigned.
