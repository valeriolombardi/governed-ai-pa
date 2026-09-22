# PICEE-PA - Technical Discussion and Validation Paper v1.1

**Date:** 22 September 2026  
**Status:** v1.1 validation release; open to external technical review

PICEE-PA is an independent, vendor-neutral public-administration application profile for governing AI-initiated actions. It was published on the Interoperable Europe Portal on 2 September 2026 and is marked **Under development**. The portal states that it is not a standard, certification scheme or legal-compliance claim.

## Executive summary

The central question is: when an AI system is technically able to execute an administrative action, how can administrative authority, technical authorization, execution and evidence be connected in a way that is explicit, reusable and reconstructible?

This v1.1 strengthens the validation method. The previous PoC used a weak baseline. The revised PoC uses the same principal, action, resource and contextual conditions in both the baseline and PICEE-PA paths.

**Result:** both paths produce the same authorization decisions in all tested scenarios. The PoC therefore does not demonstrate a new authorization capability. The remaining testable value is narrower: an explicit and portable structure for administrative execution context and evidence that can bind the authorized context to the executed action.

## 1. Current status and external placement

- Published on the Interoperable Europe Portal on 2 September 2026.
- Owner identified by the portal: Valerio Lombardi.
- Status: Under development.
- Explicitly not a standard, certification scheme or legal-compliance claim.
- Public repository includes specifications, schemas, examples, a minimal reference implementation and tests.

## 2. Model

**Policy -> Identity -> Capability -> Execution -> Evidence**

- **Policy:** purpose, rules, constraints, process context and risk.
- **Identity:** principal, AI agent/workload, sponsor and delegation chain.
- **Capability:** bounded action, resource/data scope and operational limits.
- **Execution:** runtime enforcement, approvals, isolation and failure handling.
- **Evidence:** durable information needed to reconstruct authorization, execution, outcome and provenance.

**AEE (Administrative Execution Envelope)** is the structured pre-execution authority/context.

**AEB (Administrative Evidence Bundle)** is the structured post-execution evidence package.

## 3. Existing stack and methodological position

The EU AI Act, AgID guidance, NIST AI RMF, IAM/workload identity, Cedar, OPA/Rego, API gateways and audit/provenance technologies already cover substantial parts of the problem. The correct test is therefore not whether these technologies can authorize an AI request, but whether a public administration can express and later reconstruct the specific administrative authority for a consequential AI-initiated action in a portable profile.

## 4. Strong baseline

The v1.1 baseline is Cedar-like in its principal/action/resource/context model and OPA-like in its use of structured inputs and policy evaluation. It uses the same semantic conditions as PICEE-PA: principal, AI agent, action, resource, purpose, delegation, capability, policy identifier, policy version and expiry.

## 5. PoC results

| Scenario | Strong baseline | PICEE-PA | Interpretation |
| --- | --- | --- | --- |
| Authorized action | ALLOW / executed | ALLOW / executed | Same authorization result; PICEE-PA additionally packages AEE/AEB and hash links. |
| Wrong principal | DENY | DENY | No decision advantage demonstrated. |
| Wrong AI agent | DENY | DENY | No decision advantage demonstrated. |
| Expired capability | DENY | DENY | No decision advantage demonstrated. |
| Wrong capability | DENY | DENY | No decision advantage demonstrated. |
| Wrong action | DENY | DENY | No decision advantage demonstrated. |
| Stale policy version | DENY | DENY | No decision advantage demonstrated. |

## 6. What the PoC demonstrates

1. Existing context-rich authorization technology can reproduce the same allow/deny outcomes as the minimal PICEE-PA logic.
2. PICEE-PA should not be positioned as a new authorization engine.
3. AEE/AEB provide an explicit portable structure for administrative execution context and evidence.
4. Hash-linked evidence provides a concrete mechanism for binding the evidence package to the AEE representation used for the decision.

## 7. What remains unproven

The PoC does **not** establish:

- that AEE/AEB are necessary;
- that existing Cedar/OPA/IAM/audit stacks cannot implement equivalent semantics;
- that PICEE-PA reduces cost or operational complexity;
- that PICEE-PA by itself satisfies any legal requirement;
- that PICEE-PA has institutional endorsement or validation.

## 8. Authority reconstruction test

Give an independent reviewer post-execution records and ask:

> Can you reconstruct why this exact AI agent was allowed to perform this exact action on this exact resource, under which administrative purpose, delegation and policy, and what actually happened?

Run the same exercise on a strong existing stack and on the same stack with PICEE-PA AEE/AEB. The metric is whether reconstruction becomes materially easier, more interoperable or more reliable.

## 9. Falsifiable outcomes

Three outcomes remain open:

- **Material profile value:** independent reviewers find a reusable administrative/evidence layer not conveniently standardized by the baseline stack.
- **Narrow application profile:** PICEE-PA is useful primarily as an interoperability/documentation profile around existing authorization and audit components.
- **Substantial redundancy:** existing technologies already provide equivalent portable semantics with less complexity; PICEE-PA should be redesigned or retired.

## 10. Defensible positioning

PICEE-PA is a vendor-neutral public-administration application profile for connecting administrative authority, technical authorization, execution and evidence around consequential AI-initiated actions. It builds on existing authorization and policy technologies rather than replacing them.

## References

- Interoperable Europe - PICEE-PA: https://interoperable-europe.ec.europa.eu/collection/egovernment/solution/picee-pa
- EU AI Act - Regulation (EU) 2024/1689: https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng
- AgID - Artificial Intelligence: https://www.agid.gov.it/it/ambiti-intervento/intelligenza-artificiale
- AgID - 2026 consultation: https://www.agid.gov.it/it/notizie/linee-guida-su-ia-nella-pa-al-la-consultazione-pubblica-su-sviluppo-e-procurement
- NIST AI RMF 1.0: https://www.nist.gov/itl/ai-risk-management-framework
- Cedar - Authorization: https://docs.cedarpolicy.com/auth/authorization.html
- Open Policy Agent: https://www.openpolicyagent.org/docs
- PICEE-PA repository: https://github.com/valeriolombardi/governed-ai-pa

**Versioning note:** the v1.1 release should be associated with the new Zenodo version DOI once the release is archived. Repository citation metadata and the website should then point to that v1.1 DOI.
