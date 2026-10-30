# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

QuantumShield is a research-oriented secure file-sharing platform designed to explore how modern applications can prepare for the transition to **post-quantum cryptography**.

The system combines conventional symmetric encryption with standardized post-quantum cryptography, hybrid key establishment, digital signatures, adaptive security selection, crypto-agility, recipient-specific key protection, access revocation, benchmarking, and security testing.

Instead of encrypting large files directly using public-key cryptography, QuantumShield follows an **envelope-encryption architecture**:

1. A fresh AES key encrypts the file.
2. The AES key is protected separately for the owner and every recipient.
3. ML-KEM or hybrid X25519 + ML-KEM is used to establish the key-encryption material.
4. ML-DSA signatures verify the sender and protect important metadata from tampering.
5. The encrypted file itself is stored only once.

The project is intended for research and academic demonstration. It is **not a production-audited or zero-knowledge file-sharing platform**.

---

# Table of Contents

- Overview
- Problem Statement
- Main Objectives
- Core Concepts
- System Architecture
- Cryptographic Architecture
- Supported Security Levels
- Adaptive Security Selection
- Crypto-Agility
- Hybrid Cryptography
- Digital Signatures
- Secure File Sharing
- Access Revocation
- Complete Workflow
- Technology Stack
- Project Structure
- Database Overview
- Security Features
- Benchmarking and Research Evaluation
- Experimental Results
- Security Testing
- Setup Requirements
- Environment Configuration
- Backend Run Commands
- Frontend Run Commands
- Useful Development Commands
- Important Limitations
- Future Improvements
- Project Contribution
- Documentation
- Conclusion

---

# 1. Overview

Traditional secure file-sharing applications usually use a combination of:

- symmetric encryption for files
- RSA or elliptic-curve cryptography for key exchange
- digital signatures for authenticity

The problem is that sufficiently powerful future quantum computers could threaten many widely deployed classical public-key algorithms.

QuantumShield explores a migration-oriented architecture using standardized post-quantum algorithms while still keeping the system practical.

The core design combines:

- **AES-256-GCM** for file encryption
- **ML-KEM** for post-quantum key establishment
- **X25519** for classical key agreement in hybrid mode
- **HKDF-SHA256** for secure key derivation
- **ML-DSA** for post-quantum digital signatures
- **adaptive security policies** for selecting ML-KEM security levels
- **crypto-agile providers and suites** so algorithms can evolve later

---

# 2. Problem Statement

Secure file-sharing systems need confidentiality, integrity, authentication, access control, and efficient multi-user sharing.

However, simply replacing RSA or ECC with a post-quantum algorithm is not enough.

A practical post-quantum-ready application should also support:

- multiple security configurations
- algorithm migration
- backward compatibility
- efficient file encryption
- multiple recipients
- sender authentication
- access revocation
- performance evaluation
- secure failure handling

QuantumShield addresses these requirements through an integrated crypto-agile architecture.

---

# 3. Main Objectives

QuantumShield is designed to:

- securely encrypt uploaded files
- provide post-quantum key establishment
- support multiple ML-KEM security levels
- automatically select an appropriate level using policy rules
- support hybrid classical + post-quantum protection
- securely share one encrypted file with multiple recipients
- digitally sign files and shares
- verify sender authenticity
- revoke future access to shared files
- preserve backward-compatible cryptographic metadata
- benchmark classical, post-quantum, and hybrid approaches
- compare adaptive security against always using the strongest configuration
- test the implementation against common attacks and corrupted data

---

# 4. Core Cryptographic Concepts

## AES-256-GCM

AES-256-GCM is used to encrypt the actual file.

AES is a symmetric encryption algorithm, meaning the same secret key is used for encryption and decryption.

QuantumShield generates a **fresh random 256-bit AES key for every file**.

AES-GCM provides:

- confidentiality
- integrity
- authentication of ciphertext

Large files are encrypted using AES instead of ML-KEM because symmetric encryption is much more efficient for bulk data.

---

## ML-KEM

ML-KEM is a standardized **post-quantum Key Encapsulation Mechanism**.

It is not used to encrypt the file itself.

Instead, it is used to establish shared secret material between the sender and recipient.

QuantumShield supports:

- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024

The shared secret produced by ML-KEM is passed through HKDF to derive a Key Encryption Key.

That derived key protects the AES file key.

---

## X25519

X25519 is a classical elliptic-curve key-agreement algorithm.

QuantumShield uses it only in **Hybrid mode**.

Hybrid mode combines:

```text
X25519 shared secret
+
ML-KEM shared secret
        ↓
HKDF-SHA256
        ↓
Hybrid Key Encryption Key
```

This allows the system to combine classical and post-quantum key-establishment mechanisms during a cryptographic transition period.

Hybrid security does not mean that the security levels simply add together.

---

## HKDF-SHA256

HKDF is a Key Derivation Function.

QuantumShield uses:

```text
HKDF-SHA256
```

to convert shared secret material into a cryptographically suitable 256-bit key.

For example:

```text
ML-KEM Shared Secret
        ↓
HKDF-SHA256
        ↓
256-bit KEK
```

or in hybrid mode:

```text
X25519 Secret
+
ML-KEM Secret
        ↓
HKDF-SHA256
        ↓
256-bit Hybrid KEK
```

---

## Key Encryption Key — KEK

A KEK is not the key that encrypts the file.

It is used to protect another key.

QuantumShield has:

```text
File
 ↓
AES File Key
 ↓
Encrypted File
```

The AES file key is then protected using:

```text
ML-KEM / Hybrid
        ↓
Shared Secret
        ↓
HKDF
        ↓
KEK
        ↓
Wrapped AES File Key
```

This is called **envelope encryption**.

---

## ML-DSA

ML-DSA is a post-quantum digital signature algorithm.

It is used to verify:

- who created or shared a file
- whether signed metadata was modified
- whether a ciphertext package was replaced
- whether a share is actually intended for a particular recipient

ML-DSA is not used for encryption.

Its job is **authenticity and integrity**.

---

# 5. High-Level System Architecture

```mermaid
flowchart TD

    USER[User]
    UI[React + Vite Frontend]
    API[FastAPI Backend]

    AUTH[Authentication & Authorization]
    POLICY[Adaptive Security Policy]
    FILE[File Service]
    SHARE[Sharing Service]

    SUITE[Crypto Suite Registry]
    CRYPTO[Crypto Orchestration Layer]

    AES[AES-256-GCM]
    KEM[ML-KEM]
    X[X25519]
    KDF[HKDF-SHA256]
    SIG[ML-DSA]

    DB[(PostgreSQL)]
    STORE[(Encrypted File Storage)]

    USER --> UI
    UI --> API

    API --> AUTH
    API --> FILE
    API --> SHARE
    API --> POLICY

    POLICY --> SUITE

    FILE --> CRYPTO
    SHARE --> CRYPTO

    CRYPTO --> SUITE

    SUITE --> AES
    SUITE --> KEM
    SUITE --> X
    SUITE --> KDF
    SUITE --> SIG

    API --> DB
    FILE --> STORE
```

---

# 6. File Encryption Architecture

Every file receives its own AES key.

```text
Original File
     ↓
Generate Random AES-256 Key
     ↓
Generate Fresh GCM Nonce
     ↓
AES-256-GCM
     ↓
Encrypted File
```

The plaintext file is not intentionally stored permanently.

Only the encrypted file is stored.

---

# 7. AES Key Protection

The AES key must also be protected.

For post-quantum-only mode:

```text
Recipient ML-KEM Public Key
        ↓
ML-KEM Encapsulation
        ↓
ML-KEM Shared Secret
        ↓
HKDF-SHA256
        ↓
KEK
        ↓
AES-GCM Key Wrapping
        ↓
Protected File AES Key
```

For hybrid mode:

```text
Recipient X25519 Public Key
        +
Recipient ML-KEM Public Key
        ↓
Ephemeral X25519 Agreement
        +
ML-KEM Encapsulation
        ↓
X25519 Shared Secret
        +
ML-KEM Shared Secret
        ↓
HKDF-SHA256
        ↓
Hybrid KEK
        ↓
Protect AES File Key
```

---

# 8. Supported Security Levels

QuantumShield provides three application security levels.

| Security Level | ML-KEM |
|---|---|
| LOW | ML-KEM-512 |
| STANDARD | ML-KEM-768 |
| HIGH | ML-KEM-1024 |

These labels are application policy abstractions.

They do not mean that LOW is insecure or HIGH must be used for every file.

---

# 9. Security Architectures

QuantumShield supports two main architectures.

## PQ_ONLY

Uses:

```text
AES-256-GCM
+
ML-KEM
+
HKDF-SHA256
+
ML-DSA
```

Example:

```text
STANDARD
→ ML-KEM-768
```

---

## HYBRID

Uses:

```text
AES-256-GCM
+
X25519
+
ML-KEM
+
HKDF-SHA256
+
ML-DSA
```

Example:

```text
STANDARD
→ X25519 + ML-KEM-768
```

---

# 10. Adaptive Security Selection

QuantumShield supports three selection modes:

## MANUAL

The user chooses:

```text
LOW
STANDARD
HIGH
```

---

## RECOMMEND

The system evaluates metadata and recommends a level.

The user may accept or choose another valid level.

---

## AUTO

The system automatically chooses the security level using deterministic policy rules.

No machine-learning model is currently used.

---

# 11. Adaptive Policy Inputs

The policy engine can consider metadata such as:

- sensitivity
- document category
- filename/extension
- application policy

Example sensitivity values:

```text
PUBLIC
INTERNAL
CONFIDENTIAL
HIGHLY_CONFIDENTIAL
```

Example categories:

```text
GENERAL
ACADEMIC
PERSONAL
FINANCIAL
LEGAL
MEDICAL
SOURCE_CODE
IDENTITY
CREDENTIALS
ARCHIVE
OTHER
```

---

# 12. Strongest-Rule Policy

QuantumShield follows a strongest-required-level strategy.

Example:

```text
Sensitivity = INTERNAL
→ STANDARD

Category = MEDICAL
→ HIGH

Final Result:
HIGH
```

The application never lowers a stronger applicable requirement merely because another rule requests a lower level.

---

# 13. Crypto-Agility

Crypto-agility means the application does not tightly couple business logic to one algorithm.

Instead of writing:

```text
FileService
    → directly call ML-KEM-768
```

QuantumShield uses:

```text
FileService
    ↓
Crypto Suite
    ↓
Crypto Suite Registry
    ↓
Cryptographic Providers
```

This makes future migration easier.

---

# 14. Crypto Suites

Examples of the project's suite concept include:

```text
QS-PQ-512-V1
QS-PQ-768-V1
QS-PQ-1024-V1
```

and:

```text
QS-HYBRID-512-V1
QS-HYBRID-768-V1
QS-HYBRID-1024-V1
```

A suite defines the exact algorithms required for a protected file.

Example:

```text
QS-HYBRID-768-V1

Content Encryption:
AES-256-GCM

Classical Agreement:
X25519

Post-Quantum KEM:
ML-KEM-768

KDF:
HKDF-SHA256

Key Wrapping:
AES-256-GCM
```

The suite ID is stored with the file so historical files can be decrypted using the correct algorithms.

---

# 15. Multi-Recipient Secure Sharing

QuantumShield does not encrypt the entire file again for every recipient.

Instead:

```text
                     Encrypted File
                           |
           +---------------+---------------+
           |               |               |
        Owner AES       Bob AES         Charlie AES
        Key Package     Key Package      Key Package
```

There is still only one encrypted physical file.

Each recipient receives their own protected copy of the file AES key.

This makes multi-user sharing much more efficient.

---

# 16. Secure Sharing Workflow

Suppose Alice wants to share a file with Bob.

```text
Alice's Encrypted File
        ↓
Recover Existing File AES Key
        ↓
Load Bob's Public Crypto Keys
        ↓
ML-KEM or Hybrid Key Establishment
        ↓
Derive Recipient-Specific KEK
        ↓
Protect Same AES File Key
        ↓
Generate Bob-Specific Key Package
        ↓
Create Share Metadata
        ↓
Sign Share With Alice's ML-DSA Key
```

The file itself is not re-encrypted.

---

# 17. Download Workflow

When Bob downloads a shared file:

```text
Bob Login
   ↓
JWT Authentication
   ↓
Authorization Check
   ↓
Check Share Status
   ↓
Verify Alice's ML-DSA Signature
   ↓
Load Bob's Private Key
   ↓
ML-KEM / Hybrid Key Recovery
   ↓
HKDF
   ↓
Recover KEK
   ↓
Unwrap AES File Key
   ↓
AES-256-GCM Decrypt
   ↓
Original File
```

If any required verification fails, the download is rejected.

---

# 18. Digital Signature Workflow

QuantumShield signs important security metadata.

Conceptually:

```text
Encrypted File
       ↓
SHA-256 Ciphertext Digest
       ↓
Canonical Metadata
       ↓
ML-DSA Private Key
       ↓
Digital Signature
```

The receiver verifies:

```text
Canonical Metadata
+
Signature
+
Sender's ML-DSA Public Key
        ↓
Verify
        ↓
VALID / INVALID
```

Only valid signed packages proceed through the trusted download flow.

---

# 19. What Is Signed?

Signed metadata can include important information such as:

- file ID
- ciphertext digest
- sender ID
- recipient ID
- share ID
- crypto suite
- file size
- cryptographic metadata digest
- signing-key version
- payload version

This prevents several types of metadata substitution attacks.

---

# 20. Access Revocation

The owner can revoke a recipient's future access.

Lifecycle:

```text
Share Created
     ↓
ACTIVE
     ↓
Recipient Can Download
     ↓
Owner Revokes
     ↓
REVOKED
     ↓
Future Download Rejected
```

The recipient's key-access package is no longer accepted by the application.

---

## Important Revocation Limitation

QuantumShield cannot remove a plaintext file that the recipient already downloaded before revocation.

Revocation means:

> future access through QuantumShield is blocked.

It does not mean:

> previously downloaded data disappears from the recipient's device.

---

# 21. Re-Sharing After Revocation

A revoked share is not simply reactivated.

Instead, QuantumShield creates a new share with fresh cryptographic material.

This may include:

- new KEM ciphertext
- new KDF salt
- new wrapping nonce
- new hybrid ephemeral X25519 public key
- new ML-DSA share signature

The old revoked share remains part of the history.

---

# 22. Complete End-to-End Workflow

The overall workflow is:

```text
User Registration
        ↓
Generate User Crypto Keys
        ↓
Login
        ↓
Select File
        ↓
Choose PQ_ONLY or HYBRID
        ↓
MANUAL / RECOMMEND / AUTO Security Selection
        ↓
LOW / STANDARD / HIGH
        ↓
Select Crypto Suite
        ↓
Generate Fresh AES-256 File Key
        ↓
AES-256-GCM Encrypt File
        ↓
Protect AES Key Using ML-KEM or Hybrid Mode
        ↓
Generate ML-DSA Signature
        ↓
Store Encrypted File + Safe Metadata
        ↓
User Can Download or Share
        ↓
Recipient-Specific Key Package Created
        ↓
Share Package Signed
        ↓
Recipient Verifies Signature
        ↓
Recipient Recovers AES Key
        ↓
AES Decryption
        ↓
Original File
```

---

# 23. Technology Stack

## Frontend

- React
- Vite
- JavaScript
- REST API integration
- charting/dashboard components

## Backend

- Python
- FastAPI
- Pydantic
- Pydantic Settings
- SQLAlchemy
- Alembic

## Database

- PostgreSQL

## Authentication

- JWT
- secure password hashing

## Cryptography

- AES-256-GCM
- ML-KEM-512
- ML-KEM-768
- ML-KEM-1024
- X25519
- HKDF-SHA256
- ML-DSA
- SHA-256

## Testing

- Pytest
- security integration tests
- cryptographic round-trip tests

---

# 24. Database Overview

The application contains entities conceptually similar to:

```text
User
 |
 +-- UserCryptoKeys
 |
 +-- Files
      |
      +-- CryptoMetadata
      |
      +-- FileShares
              |
              +-- Recipient Crypto Metadata
              |
              +-- Digital Signature

Audit Logs

Benchmark Runs

Adaptive Experiment Results
```

Exact table and field names should be checked in the current SQLAlchemy models.

---

# 25. User Cryptographic Keys

A user may have:

```text
ML-KEM-512 keypair
ML-KEM-768 keypair
ML-KEM-1024 keypair
X25519 keypair
ML-DSA signing keypair
```

Public keys can be stored normally.

Private keys are protected before being stored.

---

# 26. Server-Managed Key Model

QuantumShield currently uses a trusted backend architecture.

Private user keys are protected using an application master key.

Therefore:

```text
Backend = Trusted Component
```

This means QuantumShield is not a zero-knowledge system.

The backend can recover key material required for authorized operations.

A future version could move key custody to client devices or hardware-backed key stores.

---

# 27. Security Features

QuantumShield includes protection against many common implementation problems.

Examples include:

- JWT authentication
- ownership validation
- IDOR protection
- recipient authorization
- path-traversal prevention
- secure internal filenames
- upload-size restrictions
- AES-GCM tamper detection
- ML-KEM key mismatch handling
- hybrid key mismatch handling
- ML-DSA signature verification
- algorithm-confusion protection
- no silent algorithm downgrade
- share revocation
- crypto version validation
- secret-safe logging
- input validation
- safe error handling

---

# 28. Fail-Closed Design

Security-sensitive failures are designed to deny access.

Conceptually:

```text
Authenticate
    ↓
Authorize
    ↓
Check Share Status
    ↓
Validate Crypto Metadata
    ↓
Verify Signature
    ↓
Recover Key
    ↓
Verify AES-GCM Authentication
    ↓
Return File
```

If any required check fails:

```text
STOP
↓
Reject Request
```

The system should never intentionally return partially decrypted plaintext.

---

# 29. Benchmarking

QuantumShield includes an offline benchmarking framework for comparing cryptographic configurations.

The benchmark system evaluates areas such as:

- ML-KEM key generation
- ML-KEM encapsulation
- ML-KEM decapsulation
- X25519 operations
- HKDF
- AES encryption
- AES decryption
- ML-DSA signing
- ML-DSA verification
- total crypto-suite time
- key sizes
- KEM ciphertext sizes
- metadata overhead
- file-size scaling
- multi-recipient scaling

---

# 30. Compared Configurations

The project can compare configurations such as:

```text
Classical baseline

ML-KEM-512

ML-KEM-768

ML-KEM-1024

X25519 + ML-KEM-512

X25519 + ML-KEM-768

X25519 + ML-KEM-1024
```

The AES file-encryption algorithm remains constant so that differences mainly reflect key-establishment choices.

---

# 31. Adaptive vs Fixed-HIGH Evaluation

One of the main research questions is:

> Can adaptive security selection reduce computational and metadata overhead compared with always using the strongest supported configuration while still satisfying the configured security policy?

The evaluation compares:

```text
Adaptive
vs
Fixed HIGH
```

For the same scenarios.

Adaptive can choose:

```text
LOW
STANDARD
HIGH
```

while Fixed HIGH always chooses:

```text
HIGH
```

---

# 32. Current Experimental Results

The recorded standard adaptive evaluation contains:

```text
24 scenarios
×
30 measured pairs
```

Observed mean crypto time:

```text
Adaptive:
38.565 ms

Fixed HIGH:
39.931 ms
```

Observed difference:

```text
3.422%
```

Aggregate measured metadata:

```text
Adaptive:
545,514 bytes

Fixed HIGH:
568,234 bytes
```

Observed metadata difference:

```text
3.998%
```

These values are **single-machine synthetic benchmark observations**.

They should not be interpreted as universal real-world performance guarantees.

Hardware, operating system, cryptographic libraries, Python runtime, background processes, and benchmark configuration can all affect the measurements.

---

# 33. Verification Status

The project has recorded successful checks including:

```text
277 backend tests
```

The earlier dedicated final verification included:

```text
267 backend tests

88 dedicated security tests
```

along with:

- cryptographic diagnostics
- frontend lint/build checks
- suite round-trip checks
- hybrid cryptographic tests
- digital-signature verification
- application health checks
- dashboard/research page checks

Refer to the repository's verification documentation for the exact scope of each run.

---

# 34. Security Testing

The security test suite covers attack/failure scenarios including:

- invalid JWT
- JWT tampering
- unauthorized file access
- IDOR
- unauthorized share access
- path traversal
- malicious filenames
- oversized uploads
- AES ciphertext tampering
- AES nonce tampering
- wrapped-key tampering
- incorrect ML-KEM private keys
- ML-KEM ciphertext tampering
- X25519 key mismatch
- hybrid metadata swapping
- ML-DSA signature tampering
- wrong signing keys
- ciphertext replacement
- algorithm confusion
- revoked-share reuse
- malformed metadata
- unsupported crypto versions
- missing files
- missing crypto metadata
- error leakage
- secret logging

---

# 35. Project Structure

A simplified structure is:

```text
Data Security Project/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── crypto/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── benchmarks/
│   │
│   ├── alembic/
│   ├── tests/
│   ├── scripts/
│   ├── storage/
│   ├── .env
│   ├── .env.example
│   └── requirements.txt
│
├── frontend/
│   ├── src/
│   ├── public/
│   └── package.json
│
├── docs/
│
├── README.md
└── ROADMAP.md
```

The exact structure may contain additional modules.

---

# 36. Local Requirements

Before starting the application, make sure you have:

- Python
- Node.js
- PostgreSQL
- required Python dependencies
- required post-quantum cryptography library
- backend virtual environment
- valid backend `.env`
- PostgreSQL database

---

# 37. Environment Configuration

The backend requires environment variables such as:

```env
APP_NAME=QuantumShield
APP_ENV=development
DEBUG=true

DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@127.0.0.1:5433/quantumshield

SECRET_KEY=YOUR_SECRET_KEY

MASTER_KEY_BASE64=YOUR_32_BYTE_BASE64_MASTER_KEY

FRONTEND_URL=http://localhost:5173

ACCESS_TOKEN_EXPIRE_MINUTES=60

STORAGE_PATH=storage
```

Do not commit your real `.env`.

The repository should keep:

```text
.env
```

inside `.gitignore`.

The safe template:

```text
.env.example
```

may be committed.

---

# 38. Generate SECRET_KEY

From the backend virtual environment:

```bat
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

Copy the output into:

```env
SECRET_KEY=...
```

---

# 39. Generate MASTER_KEY_BASE64

Run:

```bat
python -c "import secrets,base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Copy the result into:

```env
MASTER_KEY_BASE64=...
```

## Important

Do not randomly change the master key after encrypted private keys/files are being used.

The master key is required to recover protected key material.

Changing or losing it can make existing encrypted data inaccessible.

---

# 40. PostgreSQL Configuration

The current development configuration uses PostgreSQL on:

```text
127.0.0.1
```

port:

```text
5433
```

Example:

```env
DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@127.0.0.1:5433/quantumshield
```

Make sure the `quantumshield` database exists before running migrations.

---

# 41. Backend Run Commands

Open **Command Prompt**.

Go to the backend:

```bat
cd /d "D:\Data Security Project\backend"
```

Activate the virtual environment:

```bat
call .venv\Scripts\activate.bat
```

If dependencies are not installed:

```bat
pip install -r requirements.txt
```

Run database migrations:

```bat
alembic upgrade head
```

Check current migration:

```bat
alembic current
```

Run backend tests:

```bat
python -m pytest -q
```

Start the backend:

```bat
uvicorn app.main:app --reload
```

The backend should normally be available at:

```text
http://127.0.0.1:8000
```

Swagger/OpenAPI:

```text
http://127.0.0.1:8000/docs
```

---

# 42. Frontend Run Commands

Open a **second Command Prompt**.

Run:

```bat
cd /d "D:\Data Security Project\frontend"
```

Install frontend dependencies if required:

```bat
npm install
```

Start the frontend:

```bat
npm run dev
```

Vite will usually provide:

```text
http://localhost:5173
```

Use the exact URL printed in the terminal if the port changes.

---

# 43. Recommended Daily Startup

## Terminal 1 — Backend

```bat
cd /d "D:\Data Security Project\backend"

call .venv\Scripts\activate.bat

alembic upgrade head

uvicorn app.main:app --reload
```

---

## Terminal 2 — Frontend

```bat
cd /d "D:\Data Security Project\frontend"

npm run dev
```

Then open:

```text
http://localhost:5173
```

---

# 44. PostgreSQL Connection Check

You can test PostgreSQL using:

```bat
"C:\Program Files\PostgreSQL\18\bin\psql.exe" -h 127.0.0.1 -p 5433 -U postgres
```

Then inside PostgreSQL:

```sql
\l
```

to list databases.

Exit with:

```sql
\q
```

---

# 45. Useful Backend Commands

Run full tests:

```bat
python -m pytest
```

Short test output:

```bat
python -m pytest -q
```

Run security tests if the folder exists:

```bat
python -m pytest tests\security -q
```

Check crypto providers:

```bat
python scripts\check_crypto.py
```

Run final demo verification if available:

```bat
python scripts\check_final_demo.py
```

Run benchmarks:

```bat
python scripts\run_benchmarks.py --profile quick
```

Standard benchmark:

```bat
python scripts\run_benchmarks.py --profile standard
```

Run adaptive experiment:

```bat
python scripts\run_adaptive_experiment.py --profile quick
```

Standard adaptive evaluation:

```bat
python scripts\run_adaptive_experiment.py --profile standard
```

Only use scripts that exist in the current repository.

---

# 46. Useful Frontend Commands

Install dependencies:

```bat
npm install
```

Start development server:

```bat
npm run dev
```

Run lint:

```bat
npm run lint
```

Create production build:

```bat
npm run build
```

---

# 47. Main Application Pages

The frontend may include pages such as:

```text
Login

Register

Dashboard

Upload File

My Files

Shared With Me

Shared By Me

Security

Benchmarks

Adaptive Evaluation
```

---

# 48. Dashboard

The dashboard provides a summary of the system.

Possible information includes:

- number of uploaded files
- received shares
- sent shares
- active shares
- revoked shares
- cryptographic key readiness
- security-level distribution
- PQ-only vs Hybrid distribution
- adaptive-security decisions
- recent activity
- system health

---

# 49. Security Page

The security page can display safe cryptographic metadata such as:

```text
ML-KEM-512     Ready
ML-KEM-768     Ready
ML-KEM-1024    Ready
X25519         Ready
ML-DSA         Ready
```

It must never display private keys.

---

# 50. Benchmark Dashboard

Benchmark views visualize actual benchmark data.

Examples:

- KEM encapsulation time
- KEM decapsulation time
- key sizes
- ciphertext sizes
- total crypto-suite time
- AES performance by file size
- PQ-only vs Hybrid comparison
- multi-recipient performance

No fake benchmark data should be displayed.

---

# 51. Adaptive Evaluation Dashboard

The adaptive evaluation view compares:

```text
Adaptive Security
vs
Fixed HIGH
```

It may show:

- mean timing
- median timing
- P95
- metadata usage
- savings percentage
- security-level distribution
- policy compliance
- PQ-only comparison
- Hybrid comparison

Negative or insignificant results should remain visible.

---

# 52. Security Model

QuantumShield provides strong application-level security controls, but its guarantees must be interpreted correctly.

It provides:

- encrypted file storage
- authenticated encryption
- post-quantum key establishment
- hybrid key establishment
- sender authenticity
- metadata integrity
- authorization
- recipient-specific access packages
- revocation of future application access
- algorithm validation

---

# 53. Important Limitations

QuantumShield currently has several important limitations.

## Server-Managed Private Keys

Private keys are managed by the backend.

Therefore the backend is trusted.

QuantumShield is not currently a zero-knowledge system.

---

## Master Key Trust

The application master key is a major trust anchor.

If it is compromised, protected user private keys may also be compromised.

---

## Revocation

Revocation blocks future platform access.

It cannot delete plaintext copies already downloaded by a recipient.

---

## User Classification

Adaptive security depends on metadata such as sensitivity and category.

If the user incorrectly classifies a sensitive document, the policy may receive inaccurate input.

The current version does not inspect file contents.

---

## No Malware Scanning

QuantumShield encrypts and shares files securely but does not currently perform malware detection.

---

## Benchmark Scope

Performance measurements are machine-specific.

Results may change on different:

- processors
- operating systems
- cryptographic libraries
- Python versions
- storage devices
- background workloads

---

## No Formal Security Proof

The system uses standardized cryptographic algorithms, but the complete application protocol has not undergone formal cryptographic proof or professional security audit.

---

# 54. What Makes QuantumShield Different?

QuantumShield does not claim to invent AES, ML-KEM, X25519, HKDF, or ML-DSA.

Its main contribution is the **system-level integration** of these technologies.

Important aspects include:

- multiple ML-KEM security levels
- explainable adaptive security selection
- crypto-agile versioned suites
- PQ-only and Hybrid architectures
- recipient-specific envelope encryption
- ML-DSA authenticated sharing
- future-access revocation
- empirical performance benchmarking
- Adaptive vs Fixed-HIGH evaluation
- extensive security testing

---

# 55. Research Contribution

The core research idea is not:

> Can we invent another post-quantum encryption algorithm?

Instead, it is closer to:

> Can a practical file-sharing architecture dynamically choose among standardized post-quantum security configurations while remaining crypto-agile, supporting hybrid migration, and reducing unnecessary overhead?

This is evaluated through controlled benchmarks and security testing.

---

# 56. Future Improvements

Possible future extensions include:

- client-side private-key custody
- true end-to-end encryption
- hardware-backed keys
- TPM/HSM integration
- automatic key rotation
- client-side encryption before upload
- richer organization security policies
- content-aware sensitivity classification
- ML-based document classification
- additional post-quantum algorithms
- large-scale multi-user benchmarking
- cloud object storage
- enterprise authentication
- formal protocol verification
- professional penetration testing

---

# 57. Documentation

Additional technical documentation can be found under:

```text
docs/
```

Important documents may include:

```text
FINAL_REPORT.md

PROJECT_SUMMARY.md

ARCHITECTURE.md

CRYPTOGRAPHY_DESIGN.md

CRYPTO_AGILITY.md

HYBRID_CRYPTO.md

DIGITAL_SIGNATURES.md

ACCESS_REVOCATION.md

SECURITY_MODEL.md

KEY_MANAGEMENT.md

DATABASE_DESIGN.md

API_DESIGN.md

BENCHMARKING.md

ADAPTIVE_EVALUATION.md

SECURITY_TESTING.md

RESULTS_SUMMARY.md

FINAL_VERIFICATION.md

SETUP.md

COMMANDS.md

DEMO_SCRIPT.md

DEMO_CHECKLIST.md

VIVA_QUESTIONS.md

REPRODUCIBILITY.md

PAPER_OUTLINE.md
```

---

# 58. Quick Start Summary

Backend:

```bat
cd /d "D:\Data Security Project\backend"

call .venv\Scripts\activate.bat

alembic upgrade head

uvicorn app.main:app --reload
```

Frontend in another Command Prompt:

```bat
cd /d "D:\Data Security Project\frontend"

npm run dev
```

Then open:

```text
http://localhost:5173
```

Backend API:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

---

# Conclusion

QuantumShield demonstrates how a modern file-sharing application can be designed around a combination of conventional and post-quantum cryptography.

Rather than using a post-quantum algorithm in isolation, the project integrates:

```text
AES-256-GCM
+
ML-KEM
+
X25519
+
HKDF-SHA256
+
ML-DSA
+
Adaptive Security
+
Crypto-Agility
+
Envelope Encryption
+
Secure Sharing
+
Revocation
+
Benchmarking
+
Security Testing
```

The result is a research-oriented platform that explores not only how post-quantum algorithms can be integrated into an application, but also how such a system can manage multiple security levels, algorithm migration, multi-recipient sharing, authenticity, revocation, and measurable performance trade-offs.

QuantumShield should therefore be understood as an **adaptive, crypto-agile, post-quantum secure file-sharing research prototype**, rather than simply a file-encryption application.