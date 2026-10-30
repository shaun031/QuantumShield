# QuantumShield — Adaptive Crypto-Agile Post-Quantum Secure File Sharing System

This is an **unpublished outline**, not a claim of a conference paper or independent security certification. Related-work references require a deliberate, verified literature review before submission.

1. **Abstract:** problem, server-mediated architecture, standard primitives, the measured Phase 13/14 results, and explicit limits.
2. **Introduction and related work:** long-term classical public-key risk, KEM-based file-key envelopes, hybrid migration, adaptive policy, crypto-agility. Related-work papers should be verified before publication; none are invented here.
3. **Research questions and contribution:** envelope parameter-set cost (RQ1), hybrid overhead (RQ2), Adaptive versus Fixed HIGH under project policy (RQ3), file-size/recipient scaling (RQ4). Contribution is integration/evaluation, not a novel primitive.
4. **System and threat model:** trusted backend/master key, user roles, one ciphertext plus per-recipient envelopes, attacker capabilities and out-of-scope compromise.
5. **Protocol/design:** exact suite/version dispatch, AES-GCM, ML-KEM, optional X25519 combiner, HKDF, ML-DSA canonical FILE/SHARE signatures, revocation state.
6. **Adaptive policy:** `adaptive-v1` metadata rules, strongest minimum, MANUAL/RECOMMEND/AUTO semantics, no ML/content inspection.
7. **Experimental setup:** pinned versions, Windows/CPU context, seven Phase 13 modes, 20 iterations/5 warmups, 24×30 Phase 14 paired scenarios, synthetic inputs, correctness checks, and exclusions.
8. **Results:** regenerate tables from the identified completed exports with `scripts/generate_report_summary.py`; include raw-pair uncertainty and negative results, not only headline savings.
9. **Security evaluation:** Phase 16 attack matrix, two low-severity fixes, remaining untested areas and independent-review need.
10. **Discussion/limitations:** hardware and scenario dependence, HIGH timing noise, policy misclassification, server custody, no retroactive revocation, lack of production deployment evidence.
11. **Conclusion and future work:** client custody, key rotation, formal review, PostgreSQL concurrency, more diverse measured workloads.

Use only verified primary standards/library references and a subsequently verified related-work bibliography. The [final project report](FINAL_REPORT.md) is the current evidence-backed source; this outline should not be treated as a publication.
