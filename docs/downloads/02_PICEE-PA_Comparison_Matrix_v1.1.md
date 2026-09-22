# PICEE-PA - Existing Governance Stack Comparison v1.1

**Date:** 22 September 2026  
**Purpose:** Adversarially test whether PICEE-PA adds a material, reusable profile or duplicates existing mechanisms. The baseline must be strong enough to express existing authorization semantics.

| Area | Existing capability | Potential boundary / overlap | PICEE-PA position | Validation test |
| --- | --- | --- | --- | --- |
| EU AI Act | Legal/regulatory framework for AI obligations and controls; high-risk systems include record-keeping. | Does not prescribe one vendor-neutral PA execution envelope for every AI-initiated action. | Complementary application profile; not a replacement or compliance claim. | Map a concrete use case to applicable obligations. |
| AgID AI guidance | Italian PA guidance covering adoption, development and procurement; 2026 work includes autonomy levels, AI stack, logical architecture and procurement/monitoring. | Potentially substantial overlap; boundary must be demonstrated rather than assumed. | Primary Italian comparison target. | Clause-by-clause crosswalk + use case. |
| NIST AI RMF | AI risk-management framework built around Govern, Map, Measure, Manage. | Broad risk framework rather than a specific PA execution/evidence profile. | Possible governance umbrella; no replacement claim. | Crosswalk + evidence reconstruction test. |
| IAM / workload identity | Authenticates and identifies technical actors/workloads. | Identity alone does not establish purpose, bounded capability, delegation or complete evidence. | One input to the execution profile. | Authenticated-but-unauthorised case. |
| OAuth / delegated authorization | Technical delegation of access using tokens/scopes/claims. | Technical delegation is not necessarily the whole administrative context or accountability chain. | Use existing mechanisms; bind semantics around the action. | Delegated-action test. |
| Cedar | Authorization over principal, action, resource and context, producing Allow/Deny. | Strong technical authorization primitive; can express rich context. | Do not duplicate authorization logic; test profile/value above it. | Same decision inputs, compare evidence structure. |
| OPA / Rego | General-purpose policy engine over structured input; policy as code. | Can encode many purpose, context and technical rules. | Integrate as policy decision/enforcement component. | Same policy inputs + audit path. |
| API gateway / enforcement point | Authentication, routing and policy enforcement hooks at service boundary. | Not itself a complete administrative authority model. | Execution boundary; profile can sit above/beside it. | Trace decision-to-execution binding. |
| Audit / SIEM | Events for operational logging and investigation. | Logs can be detailed yet inconsistent across systems; semantic binding may be missing. | AEB proposes a portable evidence structure. | Reconstruction exercise. |
| Provenance | Captures entity/activity/agent relationships and derivation. | Provenance is not itself an administrative authorization decision. | Reuse provenance concepts where useful. | Origin/activity/agent reconstruction. |
| Human approval | Human review or escalation before/within execution. | Approval can be detached from exact identity, capability, policy version and execution evidence. | Bind approval to the exact execution context where required. | Approval mismatch / stale approval. |
| PICEE-PA | Policy -> Identity -> Capability -> Execution -> Evidence; AEE/AEB artefacts. | Distinct value is not yet an established fact. | Treat as a testable application profile, not a new authorization engine. | Independent review + strong-baseline PoC. |

## Current conclusion
The v1.1 PoC shows no difference in authorization outcomes. The remaining hypothesis concerns standardized administrative execution context and portable evidence reconstruction, not basic authorization.

## Primary source set
- **Interoperable Europe - PICEE-PA:** Portal entry; published 2 September 2026; status Under development. https://interoperable-europe.ec.europa.eu/collection/egovernment/solution/picee-pa
- **EU AI Act - Regulation (EU) 2024/1689:** Current consolidated text checked 27 July 2026; Article 12 includes record-keeping requirements for high-risk AI. https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng
- **AgID - Artificial Intelligence:** Italian public-administration AI guidance and 2026 development/procurement work. https://www.agid.gov.it/it/ambiti-intervento/intelligenza-artificiale
- **AgID - 2026 consultation:** Development/procurement guidance; autonomy levels, AI stack, logical architecture and procurement/monitoring. https://www.agid.gov.it/it/notizie/linee-guida-su-ia-nella-pa-al-la-consultazione-pubblica-su-sviluppo-e-procurement
- **NIST AI RMF 1.0:** Govern, Map, Measure, Manage; voluntary risk-management framework. https://www.nist.gov/itl/ai-risk-management-framework
- **Cedar - Authorization:** Authorization request uses principal, action, resource and context; decision Allow/Deny. https://docs.cedarpolicy.com/auth/authorization.html
- **Open Policy Agent:** General-purpose policy engine using structured inputs and policy-as-code with Rego. https://www.openpolicyagent.org/docs