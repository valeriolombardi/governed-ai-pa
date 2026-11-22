"""
PICEE-PA v1.2 Core Data Models
Policy, Identity, Capability, Execution, Evidence specification for Public Administration.
Conforms to EU AI Act (Art. 12 & 14) and Italian CAD (Art. 20, 21, 23).
"""

from __future__ import annotations
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ActionClass(str, Enum):
    """
    Taxonomy of AI action classes in Public Administration:
    - L0: Assistive (read-only, synthesis, draft suggestions without external mutation).
    - L1: Preparatory (triage, document preparation, internal queueing).
    - L2: Reversible state-changing (requires envelope, registered rollback plan, audit).
    - L3: Consequential / Rights / Finance / Irreversible (mandatory meaningful human authorization).
    """
    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"


@dataclass(frozen=True)
class DelegationLink:
    """
    Represents an atomic link in the delegation chain.
    PICEE-PA Invariant: Delegation MUST attenuate, never amplify, authority.
    """
    delegator_id: str
    delegator_role: str
    delegatee_id: str
    delegatee_role: str
    granted_capabilities: List[str]
    max_budget: Optional[float]
    expires_at: str  # ISO 8601 UTC


@dataclass(frozen=True)
class Capability:
    """
    Bounded operational capability granted to an AI agent for a specific execution.
    """
    action: str  # e.g. "case.update", "payment.disburse", "document.sign"
    resource: str  # e.g. "case/2026/0042", "procurement/lot_1"
    max_budget: Optional[float] = None
    expires_at: Optional[str] = None


@dataclass(frozen=True)
class Approval:
    """
    Meaningful human oversight artifact (EU AI Act Art. 14).
    """
    required: bool = False
    approval_id: Optional[str] = None
    approver_id: Optional[str] = None
    approver_role: Optional[str] = None
    signature: Optional[str] = None
    approved_at: Optional[str] = None


@dataclass(frozen=True)
class PolicyReference:
    """
    Binds the execution to a specific, immutable policy version and hash.
    Prevents Time-of-Check to Time-of-Use (TOCTOU) and policy drift attacks.
    """
    policy_id: str
    version: str
    policy_hash: str


@dataclass(frozen=True)
class RollbackPlan:
    """
    Recovery specification for L2 reversible state changes.
    """
    strategy: str  # e.g. "COMPENSATING_TRANSACTION", "SNAPSHOT_RESTORE", "NONE"
    handler: str
    rollback_payload: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AEE:
    """
    Administrative Execution Envelope (AEE) - Pre-Execution Contract.
    Connects administrative authorization (purpose, process, legal framework)
    to technical authorization (identity, capability, policy constraints).
    """
    aee_id: str
    purpose: str
    legal_framework: List[str]
    requester: Dict[str, str]  # id, role, organizational_unit
    ai_agent: Dict[str, str]   # id, model, runtime_hash
    delegation_chain: List[DelegationLink]
    action_class: ActionClass
    capability: Capability
    approval: Approval
    policy: PolicyReference
    rollback_plan: Optional[RollbackPlan] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AEB:
    """
    Administrative Evidence Bundle (AEB) - Post-Execution Evidence Package.
    Attributable, tamper-evident cryptographic record of decision, execution and outcome.
    """
    aeb_id: str
    aee_id: str
    aee_hash: str
    prev_evidence_hash: str
    chain_index: int
    decision: Decision
    decision_reason: str
    execution_status: str  # "executed", "blocked", "reviewed", "rolled_back"
    execution_target: str
    side_effects: List[Dict[str, Any]]
    timestamps: Dict[str, str]  # evaluated_at, executed_at
    evidence_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
