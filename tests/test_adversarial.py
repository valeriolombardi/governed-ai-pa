"""
Automated Adversarial Verification Suite for PICEE-PA v1.2
Direct empirical validation of hypotheses H1, H2, and H5 from VALIDATION_PLAN.md:
- H1: Lower unauthorized action rate under adversarial prompt/deputy attacks.
- H2: Cryptographic tamper detection and non-repudiation in audit trails.
- H5: Mathematical delegation attenuation (prevents recursive privilege escalation).
"""

import unittest
from datetime import datetime

import sys
from pathlib import Path
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from picee import (
    AEE,
    ActionClass,
    Decision,
    DelegationLink,
    Capability,
    Approval,
    PolicyReference,
    RollbackPlan,
    PiceeEnforcementEngine,
    PiceeEvidenceLedger,
    sha256_canonical
)

CURRENT_TIME = "2026-11-22T10:00:00+00:00"
ACTIVE_POLICIES = {
    "PA-CASE-UPDATE": {
        "version": "7.0",
        "hash": "a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef",
        "allowed_actions": {"case.update", "case.read", "case.summarize"}
    },
    "PA-FINANCIAL-DISBURSE": {
        "version": "3.2",
        "hash": "9999888877776666555544443333222211110000aaaabbbbccccddddeeeeffff",
        "allowed_actions": {"payment.disburse"}
    }
}


def create_base_aee(**overrides) -> AEE:
    """Helper creating a standard, compliant L2 AEE."""
    kwargs = dict(
        aee_id="aee-2026-0042",
        purpose="D.Lgs. 36/2023 - Aggiornamento stato fascicolo appalto PNRR",
        legal_framework=["D.Lgs. 36/2023", "CAD D.Lgs. 82/2005 Art. 20"],
        requester={"id": "pa-officer-42", "role": "Funzionario_EQ", "organizational_unit": "Sistemi_Informativi"},
        ai_agent={"id": "agent-case-01", "model": "gemini-2.5-pro", "runtime_hash": "sha256:11223344"},
        delegation_chain=[
            DelegationLink(
                delegator_id="director-07",
                delegator_role="Dirigente_Apicale",
                delegatee_id="pa-officer-42",
                delegatee_role="Funzionario_EQ",
                granted_capabilities=["case.read", "case.update"],
                max_budget=50000.0,
                expires_at="2026-11-22T18:00:00+00:00"
            )
        ],
        action_class=ActionClass.L2,
        capability=Capability(
            action="case.update",
            resource="case/2026/0042",
            max_budget=10000.0,
            expires_at="2026-11-22T12:00:00+00:00"
        ),
        approval=Approval(
            required=True,
            approval_id="appr-2026-991",
            approver_id="pa-officer-42",
            approver_role="Funzionario_EQ",
            signature="sig:ecdsa:valerio_officer_42_approved",
            approved_at="2026-11-22T09:55:00+00:00"
        ),
        policy=PolicyReference(
            policy_id="PA-CASE-UPDATE",
            version="7.0",
            policy_hash="a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef1234567890abcdef"
        ),
        rollback_plan=RollbackPlan(
            strategy="COMPENSATING_TRANSACTION",
            handler="case.rollback_to_prior_revision",
            rollback_payload={"target_revision": "rev-041"}
        )
    )
    kwargs.update(overrides)
    return AEE(**kwargs)


class TestPiceeAdversarialSuite(unittest.TestCase):
    def setUp(self):
        self.engine = PiceeEnforcementEngine(
            registered_agents={"agent-case-01": {"status": "ACTIVE"}}
        )
        self.ledger = PiceeEvidenceLedger()

    def test_01_authorized_l2_with_approval_and_rollback(self):
        """Baseline positive test: Compliant L2 envelope passes all gates."""
        aee = create_base_aee()
        decision, reason = self.engine.evaluate(aee, ACTIVE_POLICIES, CURRENT_TIME)
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(reason, "policy_satisfied")

        # Ledger append succeeds and generates valid AEB
        aeb = self.ledger.append(
            aee=aee,
            decision=decision,
            decision_reason=reason,
            execution_status="executed",
            side_effects=[{"action": "case.update", "status": "committed"}],
            evaluated_at=CURRENT_TIME,
            executed_at=CURRENT_TIME
        )
        self.assertEqual(aeb.chain_index, 0)
        self.assertTrue(aeb.evidence_hash)

        is_valid, _, _ = self.ledger.verify_integrity()
        self.assertTrue(is_valid)

    def test_02_confused_deputy_blocked(self):
        """
        Adversarial Test: An unprivileged prompt attempts to invoke an agent
        without legitimate administrative purpose or lawful framework.
        """
        aee = create_base_aee(purpose="", legal_framework=[])
        decision, reason = self.engine.evaluate(aee, ACTIVE_POLICIES, CURRENT_TIME)
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(reason, "missing_administrative_purpose")

    def test_03_delegation_capability_amplification_blocked(self):
        """
        Adversarial Test (Hypothesis H5): A delegatee attempts to claim
        a capability ('payment.disburse') not granted by the parent delegator.
        """
        chain = [
            DelegationLink(
                delegator_id="director-07",
                delegator_role="Dirigente_Apicale",
                delegatee_id="sub-agent-01",
                delegatee_role="Worker_Agent",
                # Delegator only granted case.read and case.update!
                granted_capabilities=["case.read", "case.update"],
                max_budget=1000.0,
                expires_at="2026-11-22T18:00:00+00:00"
            ),
            DelegationLink(
                delegator_id="sub-agent-01",
                delegator_role="Worker_Agent",
                delegatee_id="sub-agent-02",
                delegatee_role="Worker_Agent",
                # Attacker tries to inject payment.disburse!
                granted_capabilities=["case.read", "payment.disburse"],
                max_budget=1000.0,
                expires_at="2026-11-22T18:00:00+00:00"
            )
        ]
        aee = create_base_aee(
            delegation_chain=chain,
            capability=Capability(action="payment.disburse", resource="payment/999")
        )
        decision, reason = self.engine.evaluate(aee, ACTIVE_POLICIES, CURRENT_TIME)
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(reason, "delegation_capability_amplification_at_index_1")

    def test_04_delegation_temporal_amplification_blocked(self):
        """
        Adversarial Test (Hypothesis H5): Child delegation attempts to extend
        its validity beyond the parent's expiration timestamp.
        """
        chain = [
            DelegationLink(
                delegator_id="director-07",
                delegator_role="Dirigente_Apicale",
                delegatee_id="sub-agent-01",
                delegatee_role="Worker_Agent",
                granted_capabilities=["case.read", "case.update"],
                max_budget=1000.0,
                expires_at="2026-11-22T12:00:00+00:00"
            ),
            DelegationLink(
                delegator_id="sub-agent-01",
                delegator_role="Worker_Agent",
                delegatee_id="sub-agent-02",
                delegatee_role="Worker_Agent",
                granted_capabilities=["case.read", "case.update"],
                max_budget=1000.0,
                # Attacker extends expiration to tomorrow!
                expires_at="2026-11-23T12:00:00+00:00"
            )
        ]
        aee = create_base_aee(delegation_chain=chain)
        decision, reason = self.engine.evaluate(aee, ACTIVE_POLICIES, CURRENT_TIME)
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(reason, "delegation_temporal_amplification_at_index_1")

    def test_05_l3_consequential_action_without_human_approval_fails_closed(self):
        """
        Adversarial Test (EU AI Act Art. 14): An L3 consequential/rights action
        submitted without verified human approval artifact must fail closed.
        """
        aee = create_base_aee(
            action_class=ActionClass.L3,
            approval=Approval(required=True, approval_id=None, signature=None)
        )
        decision, reason = self.engine.evaluate(aee, ACTIVE_POLICIES, CURRENT_TIME)
        self.assertEqual(decision, Decision.REVIEW)
        self.assertEqual(reason, "human_authorization_required")

    def test_06_l2_missing_rollback_plan_fails_closed(self):
        """
        Adversarial Test: An L2 state change attempting execution without
        a registered rollback strategy is rejected.
        """
        aee = create_base_aee(rollback_plan=None)
        decision, reason = self.engine.evaluate(aee, ACTIVE_POLICIES, CURRENT_TIME)
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(reason, "l2_action_requires_valid_rollback_plan")

    def test_07_toctou_policy_drift_blocked(self):
        """
        Adversarial Test: Policy updated in active registry after envelope creation.
        Stale policy version is immediately blocked.
        """
        stale_policy = PolicyReference(
            policy_id="PA-CASE-UPDATE",
            version="6.0",  # Active is 7.0
            policy_hash="stale_hash"
        )
        aee = create_base_aee(policy=stale_policy)
        decision, reason = self.engine.evaluate(aee, ACTIVE_POLICIES, CURRENT_TIME)
        self.assertEqual(decision, Decision.DENY)
        self.assertEqual(reason, "stale_policy_version_toctou")

    def test_08_cryptographic_evidence_chain_tamper_detection(self):
        """
        Adversarial Test (Hypothesis H2): Proves that any unauthorized modification
        of historical audit entries breaks the cryptographic chain of custody.
        """
        # Append 3 legitimate bundles
        for i in range(3):
            aee = create_base_aee(aee_id=f"aee-test-{i}")
            self.ledger.append(
                aee=aee,
                decision=Decision.ALLOW,
                decision_reason="policy_satisfied",
                execution_status="executed",
                side_effects=[{"seq": i}],
                evaluated_at=CURRENT_TIME,
                executed_at=CURRENT_TIME
            )

        self.assertEqual(len(self.ledger), 3)
        is_valid, _, _ = self.ledger.verify_integrity()
        self.assertTrue(is_valid, "Pre-tamper ledger must be cryptographically sound")

        # Adversary mutates bundle #1 (tampering with decision or side_effects)
        tampered_bundle = self.ledger._chain[1].to_dict()
        tampered_bundle["execution_status"] = "tampered_unauthorized_state"
        # Re-inject tampered bundle without valid evidence_hash
        from picee import AEB
        self.ledger._chain[1] = AEB(**tampered_bundle)

        # Integrity verification MUST fail and identify index 1
        is_valid, failing_idx, fail_reason = self.ledger.verify_integrity()
        self.assertFalse(is_valid)
        self.assertEqual(failing_idx, 1)
        self.assertIn("tamper_detected_hash_mismatch", fail_reason)


if __name__ == "__main__":
    unittest.main(verbosity=2)
