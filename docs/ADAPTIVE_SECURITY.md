# Adaptive Security Policy

Phase 14 evaluates this unchanged rule-based policy against Fixed HIGH using paired synthetic workloads; see [Adaptive evaluation](ADAPTIVE_EVALUATION.md). The experiment does not change any rule below.

## Phase 9 suite output

Policy rules and level semantics are unchanged. Every `SecurityDecision` now also carries the trusted suite ID from the approved mapping: LOW → `QS-PQ-512-V1`, STANDARD → `QS-PQ-768-V1`, and HIGH → `QS-PQ-1024-V1`. The policy engine does not instantiate providers; the suite registry performs cryptographic composition.

## Implemented boundary

Phase 8 policy `adaptive-v1` deterministically selects among the existing Phase 7 security levels. It does not alter AES-256-GCM, HKDF-SHA256, ML-KEM, access control, or sharing. It does not inspect file contents, parse documents, search for keywords, call an AI service, or use a machine-learning model.

```text
Explicit file metadata + sensitivity + document category
                         ↓
               SecurityPolicyEngine
                         ↓
          independent minimum-level rules
                         ↓
        strongest requirement (LOW < STANDARD < HIGH)
                         ↓
 LOW / ML-KEM-512 | STANDARD / ML-KEM-768 | HIGH / ML-KEM-1024
                         ↓
       existing HKDF + AES-256-GCM file-key envelope
                         ↓
              one AES-256-GCM file ciphertext
```

These mappings and classifications are project policy, not universal legal, scientific, or compliance rules.

## Selection modes

| Mode | Behavior |
| --- | --- |
| `MANUAL` | User selects LOW/STANDARD/HIGH. Omission by a Phase 7-compatible client retains STANDARD. The decision records the explicit choice. |
| `RECOMMEND` | Backend evaluates metadata. User must confirm a final level. Equal or stronger choices are accepted; a level below the required recommendation is rejected. |
| `AUTO` | Backend evaluates metadata and uses the strongest result. Supplying an explicit security level is rejected as contradictory. |

## Sensitivity rules

| Sensitivity | Minimum |
| --- | --- |
| `PUBLIC` | LOW |
| `INTERNAL` | STANDARD |
| `CONFIDENTIAL` | HIGH |
| `HIGHLY_CONFIDENTIAL` | HIGH |

Sensitivity is separate from cryptographic level. It is an explicit policy input, not an intrinsic property proven by the application.

## Category rules

| Category | Minimum |
| --- | --- |
| GENERAL, ACADEMIC, ARCHIVE, OTHER | LOW |
| PERSONAL, FINANCIAL, LEGAL, SOURCE_CODE | STANDARD |
| MEDICAL, IDENTITY, CREDENTIALS | HIGH |

## Extension and default rules

The extensions `.env`, `.key`, `.pem`, `.p12`, and `.pfx` contribute HIGH. Other extensions—including `.pdf`, images, and text—do not contribute a minimum by themselves. If no rule applies because sensitivity/category are absent and no secret-bearing extension is present, the result is STANDARD. File size never reduces a requirement.

Unknown enum values are rejected. Missing optional sensitivity/category are distinct from explicit PUBLIC/GENERAL, allowing `PUBLIC + GENERAL` to result in LOW while an unclassified AUTO request defaults to STANDARD.

## Decision and privacy

Each new file stores selection mode, optional sensitivity/category, recommended level, selected level (in crypto metadata), policy version, JSON rule results/reasons, and override flag. The complete decision is owner-only because classifications such as MEDICAL may themselves be sensitive. Recipients see only the selected security level and KEM algorithm required to understand their envelope.

Historical files are not reclassified. Migration `0007_adaptive_policy` leaves their Phase 8 fields null and preserves their exact existing algorithm. Normal historical download and sharing behavior continues; the decision endpoint returns a controlled conflict when no Phase 8 decision exists.

## Limitations

- Users can mislabel metadata, and filenames/extensions can be misleading.
- No file-content inspection or semantic classification exists.
- No organization-specific policy editor or external policy database exists.
- Adaptive selection does not replace authorization, TLS, AEAD integrity, secure key custody, backups, or endpoint security.
- The trusted server continues to manage protected ML-KEM private material and plaintext processing.
