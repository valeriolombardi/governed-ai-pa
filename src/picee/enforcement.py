"""
PICEE-PA v1.2 Enforcement Engine
Policy, Capability, and Delegation Attenuation Enforcement Point (PEP/PDP).
Implements fail-closed semantics and formal attenuation invariants.
"""

from __future__ import annotations
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from .models import (
    AEE,
    ActionClass,
    Decision,
    DelegationLink,
    Capability
)


def canonical_json(value: Any) -> str:
    """Produces deterministic canonical JSON serialization (RFC 8785 subset)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_canonical(value: Any) -> str:
    """Computes SHA-256 hash of canonical JSON."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def parse_iso8601(ts_str: str) -> datetime:
    """Parses ISO 8601 timestamps with UTC timezone support."""
    clean = ts_str.replace("Z", "+00:00")
    return datetime.fromisoformat(clean)


class PiceeEnforcementEngine:
    """
    Evaluates an Administrative Execution Envelope (AEE) against administrative
    rules, active policy specifications, and formal attenuation constraints.
    """

    def __init__(self, registered_agents: Optional[Dict[str, Dict[str, Any]]] = None):
        self.registered_agents = registered_agents or {}

    def register_agent(self, agent_id: str, metadata: Dict[str, Any]) -> None:
        self.registered_agents[agent_id] = metadata

    def validate_delegation_chain(self, chain: list[DelegationLink], target_capability: Capability, current_time: datetime) -> Tuple[bool, str]:
        """
        Enforces mathematical attenuation across recursive delegation:
        1. Link continuity: delegatee(i) == delegator(i+1)
        2. Monotonic non-amplification of capabilities: Scope(i+1) <= Scope(i)
        3. Monotonic non-amplification of budget: Budget(i+1) <= Budget(i)
        4. Monotonic non-amplification of expiration: Expires(i+1) <= Expires(i)
        5. Target capability inclusion in the terminal grant.
        """
        if not chain:
            return True, "no_delegation_chain_direct_execution"

        prev_link: Optional[DelegationLink] = None
        for idx, link in enumerate(chain):
            # Check expiration of current link
            link_exp = parse_iso8601(link.expires_at)
            if link_exp <= current_time:
                return False, f"delegation_link_expired_at_index_{idx}"

            if prev_link is not None:
                # Continuity check
                if link.delegator_id != prev_link.delegatee_id:
                    return False, f"delegation_chain_broken_continuity_at_index_{idx}"

                # Capability attenuation: child cannot possess capabilities parent did not grant
                parent_caps = set(prev_link.granted_capabilities)
                child_caps = set(link.granted_capabilities)
                if not child_caps.issubset(parent_caps):
                    return False, f"delegation_capability_amplification_at_index_{idx}"

                # Budget attenuation
                if prev_link.max_budget is not None:
                    if link.max_budget is None or link.max_budget > prev_link.max_budget:
                        return False, f"delegation_budget_amplification_at_index_{idx}"

                # Temporal attenuation: child expiration cannot exceed parent expiration
                parent_exp = parse_iso8601(prev_link.expires_at)
                if link_exp > parent_exp:
                    return False, f"delegation_temporal_amplification_at_index_{idx}"

            prev_link = link

        # Terminal link must cover the requested capability
        terminal_link = chain[-1]
        if target_capability.action not in terminal_link.granted_capabilities:
            return False, "requested_capability_exceeds_terminal_delegation"

        if terminal_link.max_budget is not None and target_capability.max_budget is not None:
            if target_capability.max_budget > terminal_link.max_budget:
                return False, "requested_budget_exceeds_delegation_grant"

        return True, "delegation_attenuation_satisfied"

    def evaluate(
        self,
        aee: AEE,
        active_policies: Dict[str, Dict[str, Any]],
        current_time_str: str
    ) -> Tuple[Decision, str]:
        """
        Main evaluation entrypoint with fail-closed semantics.
        """
        try:
            curr_time = parse_iso8601(current_time_str)

            # 1. Administrative Context Validation
            if not aee.purpose or len(aee.purpose.strip()) < 3:
                return Decision.DENY, "missing_administrative_purpose"

            if not aee.legal_framework:
                return Decision.DENY, "missing_legal_framework_authorization"

            if not aee.requester.get("id"):
                return Decision.DENY, "missing_requester_identity"

            # 2. AI Agent Identity & Provenance
            agent_id = aee.ai_agent.get("id")
            if not agent_id:
                return Decision.DENY, "missing_ai_agent_id"

            if self.registered_agents and agent_id not in self.registered_agents:
                return Decision.DENY, "unknown_ai_agent"

            # 3. Delegation Attenuation
            delegation_ok, delegation_reason = self.validate_delegation_chain(
                aee.delegation_chain, aee.capability, curr_time
            )
            if not delegation_ok:
                return Decision.DENY, delegation_reason

            # 4. Capability Temporal Expiration
            if aee.capability.expires_at:
                cap_exp = parse_iso8601(aee.capability.expires_at)
                if cap_exp <= curr_time:
                    return Decision.DENY, "capability_expired"

            # 5. Policy Specification, Versioning & TOCTOU Integrity
            policy_meta = active_policies.get(aee.policy.policy_id)
            if not policy_meta:
                return Decision.DENY, "policy_not_found"

            if policy_meta.get("version") != aee.policy.version:
                return Decision.DENY, "stale_policy_version_toctou"

            if policy_meta.get("hash") and policy_meta["hash"] != aee.policy.policy_hash:
                return Decision.DENY, "policy_hash_mismatch_drift_detected"

            # Check action permission in policy
            allowed_actions = policy_meta.get("allowed_actions", set())
            if allowed_actions and aee.capability.action not in allowed_actions:
                return Decision.DENY, "action_not_allowed_by_policy"

            # 6. Action Class Verification and Human Oversight Gates (EU AI Act Art. 14)
            if aee.action_class == ActionClass.L3:
                # Consequential action requires verified human approval
                if not aee.approval.required:
                    return Decision.DENY, "l3_action_must_require_human_authorization"

                if not aee.approval.approval_id or not aee.approval.signature:
                    return Decision.REVIEW, "human_authorization_required"

            elif aee.action_class == ActionClass.L2:
                # Reversible state change requires rollback plan
                if not aee.rollback_plan or aee.rollback_plan.strategy == "NONE":
                    return Decision.DENY, "l2_action_requires_valid_rollback_plan"

                if aee.approval.required and (not aee.approval.approval_id or not aee.approval.signature):
                    return Decision.REVIEW, "approval_required"

            # All administrative, identity, capability, execution, and policy gates passed
            return Decision.ALLOW, "policy_satisfied"

        except Exception as e:
            # Strictly Fail-Closed on any unhandled parsing or evaluation exception
            return Decision.DENY, f"fail_closed_exception: {type(e).__name__}"
