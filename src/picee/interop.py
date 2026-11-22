"""
PICEE-PA Interoperability & Administrative Imputation Engine (v1.3)
Implements:
1. Constitutional & Administrative Law Compliance (L. 241/1990, CAD D.Lgs. 82/2005).
2. Consiglio di Stato Jurisprudence on Algorithmic Acts (Sentenze n. 2270/2019, 8472/2019, 881/2020):
   - Principio di non-esclusivita della decisione algoritmica (human oversight / mandatory RUP co-signature).
   - Principio di piena conoscibilita e trasparenza (deterministic execution audit trail).
   - Principio di imputabilita giuridica (clear attribution to the responsible public officer).
3. ModI (Modello di Interoperabilita AgID) & PDND (Piattaforma Digitale Nazionale Dati) Envelope Generation.
4. EU AI Act (Regulation 2024/1689) Article 14 Human Oversight Compliance for High-Risk Public Sector AI.
"""

from __future__ import annotations
import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .models import (
    AEE,
    AEB,
    ActionClass,
    Approval,
    Capability,
    Decision,
    DelegationLink,
    PolicyReference,
)


@dataclass(frozen=True)
class AdministrativeImputation:
    """
    Formal legal imputation of an automated agent action to a responsible human official (RUP / Dirigente)
    in compliance with Law 241/1990 and CAD (D.Lgs. 82/2005).
    """
    imputation_id: str
    rup_name: str
    rup_tax_code: str  # Codice Fiscale
    office_code: str    # Codice IPA / UOR dell'ente
    administrative_role: str  # RUP, DEC, Dirigente Apicale, Dirigente di Servizio
    digital_signature_token: str  # eIDAS / SPID / CIE token or detached CMS signature
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    is_exclusive_algorithmic_decision: bool = False  # Must ALWAYS be False under CdS 8472/2019

    def compute_legal_hash(self) -> str:
        payload = f"{self.imputation_id}:{self.rup_tax_code}:{self.office_code}:{self.digital_signature_token}:{self.is_exclusive_algorithmic_decision}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ModIInteropEnvelope:
    """
    AgID Modello di Interoperabilita (ModI) compliant envelope for secure data exchange
    with PDND (Piattaforma Digitale Nazionale Dati) and regional protocol gateways.
    """
    message_id: str
    issuer_ipa: str
    target_ipa: str
    action_class: str
    merkle_evidence_hash: str
    imputation_digest: str
    audit_proof: Dict[str, Any]
    security_pattern: str = "INTEGRITY_REST_01"  # ModI standard pattern
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json_modi(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


class ConsiglioDiStatoValidator:
    """
    Validates adherence to the mandatory principles established by the Council of State
    for algorithmic administrative actions in Italy:
    1. Principle of Non-Exclusivity (Sent. 8472/2019): The algorithm cannot issue final binding acts
       without human discretion and sign-off.
    2. Principle of Total Explainability & Open Code (Sent. 2270/2019): Logic, weights, and rules
       must be completely auditable.
    3. Principle of Non-Discrimination & Imputation (Sent. 881/2020): Legal liability rests
       exclusively with the physical officer named in the administrative organigram.
    """

    @staticmethod
    def validate_envelope(
        aee: AEE,
        imputation: Optional[AdministrativeImputation] = None
    ) -> Tuple[bool, List[str]]:
        violations = []

        # 1. Non-Exclusivity Principle Check (CdS 8472/2019 & CAD Art. 12)
        if aee.action_class in [ActionClass.L2, ActionClass.L3]:
            if imputation is None:
                violations.append("CdS_VIOLATION_8472: L2/L3 actions require formal AdministrativeImputation to a named RUP.")
            elif imputation.is_exclusive_algorithmic_decision:
                violations.append("CdS_VIOLATION_8472: Strict prohibition of exclusive algorithmic decisions without human sign-off.")
            elif not imputation.digital_signature_token:
                violations.append("CdS_VIOLATION_CAD24: Administrative imputation lacks valid digital signature token (CAD Art. 24).")

        # 2. Level 3 Human Approval Check (EU AI Act Art. 14 & L. 241/1990)
        if aee.action_class == ActionClass.L3:
            if not aee.approval.required:
                violations.append("EU_AI_ACT_ART14: L3 consequential actions must declare approval.required=True.")
            if not aee.approval.signature:
                violations.append("EU_AI_ACT_ART14: High-impact actions require active human digital signature before dispatch.")

        # 3. Explainability and Rule Attribution Check (CdS 2270/2019)
        if not aee.policy.policy_hash or not aee.policy.policy_id:
            violations.append("CdS_VIOLATION_2270: Action missing explicit immutable policy reference and hash.")

        if not aee.legal_framework:
            violations.append("L241_VIOLATION: Procedural action lacks normative legal reference (Art. 3 L. 241/1990 motivazione).")

        is_valid = len(violations) == 0
        return is_valid, violations


class InteropGateway:
    """
    Standardized interoperability gateway bridging PICEE-PA governance engine with
    national PA infrastructure (PDND, ModI, and protocol systems).
    """

    def __init__(self, ipa_code: str, office_code: str):
        self.ipa_code = ipa_code
        self.office_code = office_code

    def create_imputation(
        self,
        rup_name: str,
        rup_tax_code: str,
        administrative_role: str,
        digital_signature_token: str,
        is_exclusive: bool = False
    ) -> AdministrativeImputation:
        return AdministrativeImputation(
            imputation_id=str(uuid.uuid4()),
            rup_name=rup_name,
            rup_tax_code=rup_tax_code,
            office_code=self.office_code,
            administrative_role=administrative_role,
            digital_signature_token=digital_signature_token,
            is_exclusive_algorithmic_decision=is_exclusive,
        )

    def export_modi_envelope(
        self,
        aeb: AEB,
        imputation: AdministrativeImputation,
        target_ipa: str,
    ) -> ModIInteropEnvelope:
        """Packages an approved and executed decision into an AgID ModI-compliant secure payload."""
        message_id = f"urn:modi:pa:{self.ipa_code}:{uuid.uuid4()}"
        return ModIInteropEnvelope(
            message_id=message_id,
            issuer_ipa=self.ipa_code,
            target_ipa=target_ipa,
            action_class=aeb.execution_target,
            merkle_evidence_hash=aeb.evidence_hash,
            imputation_digest=imputation.compute_legal_hash(),
            audit_proof={
                "aeb_id": aeb.aeb_id,
                "aee_id": aeb.aee_id,
                "chain_index": aeb.chain_index,
                "decision": aeb.decision.value,
                "execution_status": aeb.execution_status,
                "timestamps": aeb.timestamps,
                "imputation": imputation.to_dict(),
            },
        )
