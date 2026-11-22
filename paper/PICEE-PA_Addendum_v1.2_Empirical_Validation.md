# PICEE-PA v1.2 Research Addendum: Empirical Validation and Mathematical Invariants

**Author:** Valerio Lombardi  
**ORCID:** [0009-0006-3949-6228](https://orcid.org/0009-0006-3949-6228)  
**Status:** Working Paper / Scientific Validation Addendum  
**Repository:** `valeriolombardi/governed-ai-pa`  
**License:** CC BY 4.0 (Documentation) / Apache-2.0 (Code)  

---

## Abstract

As Public Administration (PA) transitions from conversational generative AI to autonomous agentic systems capable of selecting tools, mutating administrative states, and executing operational side-effects, conventional Identity and Access Management (IAM) and prompt-level guardrails become insufficient. This paper addendum introduces the formal mathematical invariants and empirical validation results for **PICEE-PA v1.2** (Policy, Identity, Capability, Execution, Evidence). 

Through an adversarial test harness comparing a Cedar/OPA-style baseline against the PICEE-PA execution envelope architecture, we empirically prove three core hypotheses:
1. **Hypothesis H1 (Adversarial Protection):** The Administrative Execution Envelope (AEE) eliminates Confused Deputy attacks by strictly binding technical actions to verifiable administrative mandates.
2. **Hypothesis H2 (Cryptographic Non-Repudiation):** The Administrative Evidence Bundle (AEB) Merkle hash chain achieves 100% mathematical tamper detection, meeting the record-keeping standards of Art. 12 of the EU AI Act and Art. 20–23 of the Italian Digital Administration Code (CAD).
3. **Hypothesis H5 (Delegation Attenuation):** Recursive multi-agent delegations are constrained by monotonic non-amplification rules, preventing privilege escalation across autonomous subagent swarms.

---

## 1. Problem Statement: The Limits of Traditional Technical IAM in PA

In traditional enterprise IT, authorization answers: *"Does principal $P$ possess permission to call endpoint $E$?"*

In Public Administration, this question is fundamentally incomplete. Under administrative law (e.g., Italian Law 241/1990, D.Lgs. 36/2023, CAD D.Lgs. 82/2005), an administrative act is legitimate only if:
1. It is backed by an explicit statutory competence (*competenza per materia e per grado*).
2. It pursues an authorized public interest (*causa o fine istituzionale tipico*).
3. It originates from a verifiable delegation chain (*catena di deleghe e poteri di spesa/firma*).
4. It is accountable and auditable post-hoc (*imputabilità e non ripudiabilità dell'atto*).

When an AI agent acts autonomously, it lacks legal personality. Therefore, technical execution must be bound to an **Administrative Execution Envelope (AEE)** prior to execution, and sealed in an **Administrative Evidence Bundle (AEB)** post-execution.

---

## 2. Formal Mathematical Invariants

PICEE-PA establishes four formal invariants that govern all operational runtimes:

### Invariant 1: Capability Boundedness
Let $\mathcal{A}$ be the action executed, and $\mathcal{C}$ be the capability set defined in the envelope:
$$\mathcal{A} \subseteq \mathcal{C}_{\text{granted}} \quad \text{and} \quad \text{Resource}(\mathcal{A}) \in \text{Scope}(\mathcal{C})$$
Any execution outside $\mathcal{C}$ evaluates immediately to $\text{DENY}$ under fail-closed semantics.

### Invariant 2: Monotonic Delegation Attenuation
Let $D = (L_0, L_1, \dots, L_k)$ be a sequence of recursive delegations from human supervisor $L_0$ to terminal AI agent $L_k$. For all $i \in \{0, \dots, k-1\}$:
$$\text{Scope}(L_{i+1}) \subseteq \text{Scope}(L_i)$$
$$\text{Budget}(L_{i+1}) \le \text{Budget}(L_i)$$
$$\text{ExpiresAt}(L_{i+1}) \le \text{ExpiresAt}(L_i)$$
Delegation authority is strictly monotonically non-increasing. A subagent cannot be granted wider authority, greater budget, or longer lifetime than its parent delegator.

### Invariant 3: Cryptographic Audit Chain Integrity
Every evidence bundle $\text{AEB}_k$ is cryptographically linked to its predecessor $\text{AEB}_{k-1}$:
$$\text{AEB}_k.\text{prev\_evidence\_hash} = \text{AEB}_{k-1}.\text{evidence\_hash}$$
$$\text{AEB}_k.\text{evidence\_hash} = \mathcal{H}_{\text{SHA256}}\left(\text{AEB}_k \setminus \{\text{evidence\_hash}\}\right)$$
Any unauthorized modification of historical action $\text{AEB}_j$ ($j < k$) induces a cascade failure:
$$\mathcal{H}_{\text{SHA256}}(\text{AEB}_j) \neq \text{AEB}_{j+1}.\text{prev\_evidence\_hash}$$
guaranteeing immediate mathematical detection of insider tampering.

### Invariant 4: Consequential Action Gate (L3 Fail-Closed)
For any action classified as consequential, financial, rights-altering, or irreversible ($L_3$):
$$\text{ActionClass}(\text{AEE}) = L_3 \implies \left(\text{Approval}.\text{required} = \text{True} \land \text{Approval}.\text{signature} \neq \emptyset\right)$$
Absence of human authorization fails closed into $\text{REVIEW}$, preventing unverified autonomous execution.

---

## 3. Empirical Evaluation & Adversarial Benchmark

The test harness evaluated PICEE-PA v1.2 against a strong Cedar/OPA baseline across six adversarial attack vectors:

| Scenario | Threat Vector | Strong Baseline | PICEE-PA v1.2 | Empirical Finding |
| :--- | :--- | :--- | :--- | :--- |
| **1. Legitimate L2 Action** | Baseline administrative flow | `ALLOW (allowed)` | `ALLOW (policy_satisfied)` | Functional parity; PICEE-PA additionally seals cryptographic AEB. |
| **2. Confused Deputy** | Prompt injection bypassing administrative mandate | `ALLOW (VULNERABLE)` | `DENY (missing_administrative_purpose)` | **Blocked:** PICEE-PA requires explicit lawful purpose and legal framework (CAD Art. 20). |
| **3. Delegation Amplification** | Subagent claims unauthorized capability | `ALLOW (VULNERABLE)` | `DENY (delegation_capability_amplification)` | **Blocked:** Mathematical attenuation prevents privilege escalation (Hypothesis H5). |
| **4. L3 Unapproved Act** | Irreversible financial/legal side-effect | `ALLOW (VULNERABLE)` | `REVIEW (human_authorization_required)` | **Blocked:** Mandatory fail-closed human oversight gate (EU AI Act Art. 14). |
| **5. Historical Audit Tampering**| Insider modifies past execution log | `UNDETECTED (0%)` | `TAMPER DETECTED (100%)` | **Detected:** Merkle hash-chain pinpoints exact tampered index (EU AI Act Art. 12). |
| **6. Policy Drift / TOCTOU** | Active policy updated during execution | `ALLOW (VULNERABLE)` | `DENY (stale_policy_version_toctou)` | **Blocked:** Cryptographic policy hash validation prevents TOCTOU exploits. |

---

## 4. Legal Compliance Mapping

| Regulatory Provision | Statutory Requirement | PICEE-PA v1.2 Implementation |
| :--- | :--- | :--- |
| **EU AI Act Art. 12** | Automatic recording of events (*logs*) throughout lifecycle | Cryptographic Merkle Evidence Ledger generating verifiable, immutable AEBs. |
| **EU AI Act Art. 14** | Human oversight (*human-in-the-loop / human-on-the-loop*) | Strict fail-closed $L_3$ gate requiring cryptographically signed human approval. |
| **CAD (D.Lgs. 82/2005) Art. 20** | Legal validity, integrity, and non-repudiation of digital acts | Canonical JSON (RFC 8785 subset) + SHA-256 envelope and evidence bindings. |
| **CAD Art. 21 & 23** | Imputability and compliant electronic storage | Attributable delegation chain linking physical identity (SPID/CIE) to agent workload. |
| **Linee Guida AgID AI** | Tracciabilità decisionale e spiegabilità dei procedimenti | Explicit binding of administrative purpose, norm reference, and evaluation rationale. |

---

## 5. Zenodo v1.2 Release Roadmap

Following empirical validation, PICEE-PA is structured for formal archival on Zenodo:
1. Release tag: `v1.2.0-validation`.
2. Artifacts: Specification, JSON Schemas (`aee.schema.json`, `aeb.schema.json`), Reference Implementation (`src/picee`), Adversarial Test Suite (`tests/test_adversarial.py`), and Benchmark Data (`PoC_Evaluation_Results_v1.2.csv`).
3. Permanent DOI registration upon snapshot ingestion.
