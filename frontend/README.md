# QuantumShield Frontend

Phase 15 retains MANUAL, RECOMMEND, and AUTO upload modes while displaying backend-selected suites. The authenticated dashboard uses owner-scoped aggregate APIs; Security and research pages display safe metadata and real completed exports. No key material or arbitrary algorithm composition is exposed. See `../docs/UI_DASHBOARD.md`.

## Setup

```powershell
cd "D:\Data Security Project\frontend"
npm install
Copy-Item .env.example .env
npm run dev
```

Open the exact URL printed by Vite, normally <http://127.0.0.1:5173>.

## Routes

| Route | Access | Purpose |
| --- | --- | --- |
| `/register` | Signed out | Create an account |
| `/login` | Signed out | Obtain an access token |
| `/dashboard` | Authenticated | Profile, system status, and ML-KEM key status |
| `/security` | Authenticated | Key readiness, approved suites, availability, and design limitations |
| `/benchmarks` | Authenticated | Latest completed Phase 13 export, with optional local JSON import |
| `/adaptive-evaluation` | Authenticated | Latest completed Phase 14 export, with optional local JSON import |
| `/upload` | Authenticated | Select manual/recommend/auto policy metadata and upload one bounded file |
| `/files` | Authenticated | List, decrypt/download, and delete owned files |
| `/files/:fileId/share` | Authenticated owner | Search/select a recipient and create a secure share |
| `/shared-with-me` | Authenticated recipient | List and download received shares |
| `/shared-by-me` | Authenticated sender | List sent shares and their active status |

Version-2 rows show the stored level, AES-256-GCM, and exact ML-KEM algorithm. Phase 8 rows also show mode, sensitivity, recommendation, policy version, override state, and owner-only reasons. Options and mappings come from `/api/security/options`; policy decisions remain backend-authoritative.

The frontend sends plaintext over the authenticated API connection; production therefore requires HTTPS. AES encryption, ML-KEM encapsulation/decapsulation, HKDF, and key wrapping occur on the trusted backend. Authenticated downloads return original plaintext only after every KEM/KDF/GCM step succeeds.

## Configuration

```dotenv
VITE_API_BASE_URL=http://127.0.0.1:8000/api
VITE_MAX_UPLOAD_SIZE_MB=25
```

No master key or other cryptographic secret belongs in frontend configuration.

## Verification

```powershell
npm run lint
npm run build
npm audit
npm run dev
```

Manual workflow:

1. Register/login and open **Upload File**.
2. Upload a test file and confirm the encrypted success message.
3. Open **My Files** and confirm the AES-256-GCM badge.
4. Download and compare the result to the original.
5. Register a second user, search for them from the owned file's Share page, and choose **Share securely**.
6. Sign in as the recipient, open **Shared With Me**, and download/compare the file.
7. Sign in as the owner, open **Shared By Me**, and verify the recipient/status.
8. Delete the owned file and confirm it disappears from both users' views.
