# PICEE-PA Specification Draft v1.0

## Status
Design proposal. Non-normative until explicitly promoted to a conformance specification.

## Core invariant
An AI-generated intention is never, by itself, authority to create an external side effect. Every significant action MUST be mediated by an enforcement path that can validate an AEE and produce an AEB.

## PICEE layers
- **Policy**: purpose/process, applicable rules, risk, constraints.
- **Identity**: requester, agent/workload, sponsor, delegation chain.
- **Capability**: bounded action/resource/data scope/budget.
- **Execution**: fail-closed decision, approval, isolation, recovery.
- **Evidence**: attributable record of decision, execution and outcome.

## Action classes
- L0 assistive
- L1 preparatory
- L2 reversible state-changing
- L3 consequential/rights/financial/irreversible

## Minimum semantics
1. Unknown or unverifiable identity -> DENY.
2. Missing/invalid policy context for a required field -> DENY.
3. Capability outside delegated scope -> DENY.
4. L3 without required meaningful approval -> DENY.
5. Policy/runtime error at enforcement point -> fail closed.
6. Executed L2/L3 action -> generate durable AEB.
7. Policy/model/tool/schema versions SHOULD be recorded for replay/reconstruction.
8. Recursive delegation MUST attenuate, never amplify, authority.
9. Evidence SHOULD be content-minimised and integrity-protected.

## Interoperability goal
PICEE-PA is intended to map to existing policy engines and agent governance runtimes (e.g. OPA/Rego, Cedar, Microsoft ACS/AGT) rather than replace them.
