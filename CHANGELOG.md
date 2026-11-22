# Changelog

## v1.3.0 — 2026-11-22

- **Consiglio di Stato Administrative Compliance Engine (`src/picee/interop.py`):**
  - Enforced the Constitutional Principle of Non-Exclusivity of Algorithmic Decisions (Sentenza CdS n. 8472/2019): strict fail-closed rejection of autonomous administrative acts lacking human oversight.
  - Implemented total computational explainability and policy binding checks (Sentenza CdS n. 2270/2019).
  - Implemented administrative legal imputation (`AdministrativeImputation`) linking decisions to the physical RUP / Dirigente under L. 241/1990 and CAD Art. 24.
- **AgID ModI & PDND Interoperability Gateway:**
  - Implemented `ModIInteropEnvelope` conforming to AgID standard `INTEGRITY_REST_01` for secure institutional data exchange with the Piattaforma Digitale Nazionale Dati (PDND).
  - Formal JSON Schema definition in `schemas/picee_interop_v1.3.json`.
- **Institutional Research Paper (`paper/PICEE-PA_Administrative_Imputation_Paper_v1.3.md`):**
  - Formal paper by Valerio Lombardi (ORCID: `0009-0006-3949-6228`) connecting algorithmic governance, CAD, EU AI Act Art. 14, and Consiglio di Stato jurisprudence.
- **Automated Interoperability Test Suite (`tests/test_interop.py`):**
  - 13/13 passing tests across adversarial defenses and administrative law compliance.

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
