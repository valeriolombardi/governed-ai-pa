# Changelog

## v1.2.0 — 2026-11-22

- **Adversarial Benchmark & Empirical Validation:** Implemented validation harness for Hypotheses H1 (Adversarial Protection), H2 (Audit Tampering), and H5 (Delegation Attenuation).
- **Formal Attenuation Engine (`src/picee/enforcement.py`):** Enforced mathematical delegation attenuation across recursive subagent chains, blocking Confused Deputy and privilege escalation attacks.
- **Cryptographic Evidence Ledger (`src/picee/ledger.py`):** Implemented Merkle hash-chaining audit trail for AEBs with 100% mathematical tamper detection under EU AI Act Art. 12 & CAD Art. 20–23.
- **Action Class Gates (L0–L3):** Added mandatory fail-closed human oversight gates for L3 consequential administrative acts and rollback plan registration for L2 acts.
- **Automated Adversarial Test Suite (`tests/test_adversarial.py`):** 8 automated tests covering prompt injection, delegation amplification, temporal escalation, TOCTOU drift, and log tampering.
- **Scientific Research Addendum (`paper/PICEE-PA_Addendum_v1.2_Empirical_Validation.md`):** Formal documentation of mathematical invariants and empirical benchmark results.

## v1.1.0 — 2026-09-22

- Replaced the weak PoC baseline with a strong context-rich authorization baseline.
- Reframed PICEE-PA without claiming a new authorization engine.
- Added authority-reconstruction validation.
- Added comparison matrix against existing governance and authorization approaches.
- Added institutional brief.
- Added technical discussion paper focused on administrative authority, technical authorization, execution and evidence.
- Added validation PoC and automated tests.

## v1.0.0

- Initial public design proposal.
- Final Italian paper.
- AEE/AEB schemas and synthetic examples.
- Minimal reference implementation and tests.
- GitHub Pages landing page.
