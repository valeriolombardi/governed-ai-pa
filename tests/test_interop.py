#!/usr/bin/env python3
"""
Test Suite: PICEE-PA v1.3 Interoperability & Administrative Imputation Engine
Verifies compliance with:
- Consiglio di Stato Sent. 8472/2019 (Non-esclusivita della decisione algoritmica)
- Consiglio di Stato Sent. 2270/2019 (Piena conoscibilita e trasparenza)
- CAD D.Lgs. 82/2005 (Imputabilita e firma digitale ex Art. 24)
- EU AI Act Reg. 2024/1689 Art. 14 (Human Oversight)
- AgID ModI Interoperability Enveloping
"""

import json
import unittest
from datetime import datetime, timezone

from src.picee.models import (
    AEE,
    AEB,
    ActionClass,
    Approval,
    Capability,
    Decision,
    DelegationLink,
    PolicyReference,
)
from src.picee.interop import (
    AdministrativeImputation,
    ConsiglioDiStatoValidator,
    InteropGateway,
    ModIInteropEnvelope,
)


class TestAdministrativeInterop(unittest.TestCase):
    def setUp(self):
        self.gateway = InteropGateway(ipa_code="c_xxxx", office_code="UOR_DEMO_01")
        self.rup_imputation = self.gateway.create_imputation(
            rup_name="Mario Rossi",
            rup_tax_code="RSSMRA80A01H501U",
            administrative_role="Responsabile Unico del Progetto (RUP)",
            digital_signature_token="eIDAS.QES.SHA256.valid_detached_signature_token_demo",
            is_exclusive=False,
        )

        self.valid_l3_aee = AEE(
            aee_id="aee_test_interop_001",
            purpose="Liquidazione stato di avanzamento lavori SAL 2 fornitura cloud",
            legal_framework=["L. 241/1990 Art. 3", "D.Lgs. 36/2023 Art. 114", "CAD Art. 12"],
            requester={"id": "user_demo", "role": "RUP", "organizational_unit": "UOR_DEMO"},
            ai_agent={"id": "agent_procurement_01", "model": "gemini-2.5-flash", "runtime_hash": "sha256:abc123runtime"},
            delegation_chain=[
                DelegationLink(
                    delegator_id="dirigente_apicale_01",
                    delegator_role="Direttore Generale",
                    delegatee_id="user_demo",
                    delegatee_role="RUP",
                    granted_capabilities=["procurement.payment.sal"],
                    max_budget=50000.0,
                    expires_at="2027-12-31T23:59:59Z",
                )
            ],
            action_class=ActionClass.L3,
            capability=Capability(action="procurement.payment.sal", resource="sal/2026/02", max_budget=25000.0),
            approval=Approval(
                required=True,
                approval_id="appr_001",
                approver_id="user_demo",
                approver_role="RUP",
                signature="qes_signature_demo_valid",
                approved_at=datetime.now(timezone.utc).isoformat(),
            ),
            policy=PolicyReference(
                policy_id="policy_sal_disbursement",
                version="1.3.0",
                policy_hash="sha256:4f3c2b1a8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a",
            ),
        )

    def test_01_valid_administrative_proposal_passes(self):
        """A properly imputed, signed, and human-approved L3 proposal must pass all legal checks."""
        is_valid, violations = ConsiglioDiStatoValidator.validate_envelope(
            self.valid_l3_aee, self.rup_imputation
        )
        self.assertTrue(is_valid, f"Unexpected legal violations: {violations}")
        self.assertEqual(len(violations), 0)

    def test_02_exclusive_algorithmic_decision_strictly_prohibited(self):
        """Violation of Consiglio di Stato 8472/2019: Exclusive algorithmic decision must be rejected."""
        exclusive_imputation = AdministrativeImputation(
            imputation_id="imp_exclusive_01",
            rup_name="Mario Rossi",
            rup_tax_code="RSSMRA80A01H501U",
            office_code="UOR_DEMO_01",
            administrative_role="RUP",
            digital_signature_token="sig_test",
            is_exclusive_algorithmic_decision=True,  # VIOLATION: Agent acting without human oversight
        )
        is_valid, violations = ConsiglioDiStatoValidator.validate_envelope(
            self.valid_l3_aee, exclusive_imputation
        )
        self.assertFalse(is_valid)
        self.assertTrue(any("Strict prohibition of exclusive algorithmic decisions" in v for v in violations))

    def test_03_missing_digital_signature_rejected_cad_art24(self):
        """Structural validation: Imputation envelope lacking mandatory digital signature token must fail closed."""
        unsigned_imputation = AdministrativeImputation(
            imputation_id="imp_unsigned_01",
            rup_name="Mario Rossi",
            rup_tax_code="RSSMRA80A01H501U",
            office_code="UOR_DEMO_01",
            administrative_role="RUP",
            digital_signature_token="",  # Empty signature
            is_exclusive_algorithmic_decision=False,
        )
        is_valid, violations = ConsiglioDiStatoValidator.validate_envelope(
            self.valid_l3_aee, unsigned_imputation
        )
        self.assertFalse(is_valid)
        self.assertTrue(any("CAD Art. 24" in v for v in violations))

    def test_04_l3_lacking_human_approval_fails_eu_ai_act(self):
        """Violation of EU AI Act Art. 14: L3 action lacking human signature must fail."""
        unapproved_aee = AEE(
            aee_id="aee_unapproved_l3",
            purpose=self.valid_l3_aee.purpose,
            legal_framework=self.valid_l3_aee.legal_framework,
            requester=self.valid_l3_aee.requester,
            ai_agent=self.valid_l3_aee.ai_agent,
            delegation_chain=self.valid_l3_aee.delegation_chain,
            action_class=ActionClass.L3,
            capability=self.valid_l3_aee.capability,
            approval=Approval(required=True, signature=None),  # Missing active human sign-off
            policy=self.valid_l3_aee.policy,
        )
        is_valid, violations = ConsiglioDiStatoValidator.validate_envelope(
            unapproved_aee, self.rup_imputation
        )
        self.assertFalse(is_valid)
        self.assertTrue(any("EU_AI_ACT_ART14" in v for v in violations))

    def test_05_modi_envelope_generation(self):
        """AgID ModI compliant envelope generation for dispatch to PDND / Interop."""
        dummy_aeb = AEB(
            aeb_id="aeb_test_001",
            aee_id=self.valid_l3_aee.aee_id,
            aee_hash="sha256:1234567890abcdef",
            prev_evidence_hash="sha256:0000000000000000",
            chain_index=1,
            decision=Decision.ALLOW,
            decision_reason="All constraints and CdS principles verified",
            execution_status="executed",
            execution_target="procurement.payment.sal",
            side_effects=[{"payment_id": "pay_987", "amount": 25000.0}],
            timestamps={"evaluated_at": "2026-11-22T19:00:00Z", "executed_at": "2026-11-22T19:00:01Z"},
            evidence_hash="sha256:feedbeefcafe1234567890",
        )

        modi_env = self.gateway.export_modi_envelope(
            aeb=dummy_aeb,
            imputation=self.rup_imputation,
            target_ipa="r_campan",
        )

        self.assertEqual(modi_env.issuer_ipa, "c_xxxx")
        self.assertEqual(modi_env.target_ipa, "r_campan")
        self.assertEqual(modi_env.security_pattern, "INTEGRITY_REST_01")
        self.assertEqual(modi_env.imputation_digest, self.rup_imputation.compute_legal_hash())

        json_out = modi_env.to_json_modi()
        self.assertIn("INTEGRITY_REST_01", json_out)
        self.assertIn("Mario Rossi", json_out)
        self.assertIn("c_xxxx", json_out)


if __name__ == "__main__":
    unittest.main()
