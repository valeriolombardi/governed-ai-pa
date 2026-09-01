# PICEE-PA - Governed AI Execution for Public Administration

**Policy -> Identity -> Capability -> Execution -> Evidence**

PICEE-PA is an independent, vendor-neutral **design proposal / public-administration application profile** for governing AI-initiated actions. It connects administrative authorization (purpose, process, delegation and accountability) to technical authorization (identity, capabilities, policy enforcement and runtime controls), one action at a time.

Author: **Valerio Lombardi**  
ORCID: **https://orcid.org/0009-0006-3949-6228**

> Status: v1.0 design proposal. PICEE-PA is not a standard, certification, legal opinion, or compliance claim.

## Why PICEE-PA

Modern agentic systems can call tools and create side effects. General governance and technical controls already exist (EU AI Act, NIST, Canada, Microsoft Agent Governance Toolkit, OPA/Cedar, etc.). PICEE-PA does **not** claim to invent those components. It proposes a public-sector profile that makes the authorization chain explicit for each significant action:

1. **Policy** - purpose, process, rules, constraints and risk.
2. **Identity** - requester, agent/workload, sponsor and delegation.
3. **Capability** - bounded action, resource, data scope and budget.
4. **Execution** - fail-closed enforcement, approvals, isolation and recovery.
5. **Evidence** - policy decision, approval, actual side effects, provenance and versions.

Two proposed interoperable artefacts are included:

- **AEE - Administrative Execution Envelope**: pre-execution contract.
- **AEB - Administrative Evidence Bundle**: post-execution evidence package.

## Repository contents

- `paper/` - final paper (Italian; English abstract/spec summary can be added later)
- `spec/PICEE-PA-SPEC.md` - implementer-oriented specification draft
- `schemas/` - JSON Schemas for AEE and AEB
- `examples/` - synthetic example envelopes/bundles
- `src/` + `tests/` - minimal synthetic reference implementation
- `docs/` - GitHub Pages landing page
- `references/` - annotated source list

## Action classes

| Class | Meaning | Default control |
|---|---|---|
| L0 | Assistive/read/draft | proportionate logging |
| L1 | Preparatory/triage/recommend | policy + traceability + correction |
| L2 | Reversible state change | narrow capability + risk-based approval + recovery |
| L3 | Consequential/rights/finance/irreversible | meaningful human authorization by default + strong evidence |

## DOI

**DOI will be added after the first Zenodo-archived GitHub release.** Do not insert a placeholder DOI into citations.

After Zenodo archives `v1.0.0`, update this README and `CITATION.cff` with the DOI. Keep the original `v1.0.0` tag immutable; if you want the DOI embedded in a later archived snapshot, publish a follow-up patch release.

## Citation

GitHub will expose **Cite this repository** from `CITATION.cff`. A DOI-based citation will be added after Zenodo ingestion.

## Independence

This repository contains independent personal research. The views expressed are solely those of the author and do not represent any organisation, institution, or employer.

## Licensing

- Code and JSON schemas: Apache License 2.0 (`LICENSE-CODE`)
- Paper, specification, diagrams and documentation: CC BY 4.0 (`LICENSE-DOCS`)
