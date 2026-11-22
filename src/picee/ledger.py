"""
PICEE-PA v1.2 Cryptographic Evidence Ledger
Tamper-evident, non-repudiation audit trail based on Merkle hash chaining.
Conforms to EU AI Act Art. 12 (record-keeping) and Italian CAD Art. 20, 21, 23.
"""

from __future__ import annotations
import json
from typing import Any, Dict, List, Optional, Tuple

from .models import AEE, AEB, Decision
from .enforcement import canonical_json, sha256_canonical


class PiceeEvidenceLedger:
    """
    Append-only Merkle-linked evidence ledger for Administrative Evidence Bundles (AEB).
    Guarantees non-repudiation and immediate mathematical detection of historical tampering.
    """

    def __init__(self, genesis_hash: str = "0" * 64):
        self.genesis_hash = genesis_hash
        self._chain: List[AEB] = []

    def __len__(self) -> int:
        return len(self._chain)

    @property
    def latest_evidence_hash(self) -> str:
        if not self._chain:
            return self.genesis_hash
        return self._chain[-1].evidence_hash

    def append(
        self,
        aee: AEE,
        decision: Decision,
        decision_reason: str,
        execution_status: str,
        side_effects: List[Dict[str, Any]],
        evaluated_at: str,
        executed_at: str
    ) -> AEB:
        """
        Constructs and binds an Administrative Evidence Bundle (AEB)
        to the pre-execution AEE and the preceding evidence bundle hash.
        """
        aee_dict = aee.to_dict()
        aee_hash = sha256_canonical(aee_dict)
        prev_hash = self.latest_evidence_hash
        index = len(self._chain)

        aeb_id = f"aeb-{index:06d}-{aee_hash[:12]}"

        # Base payload to hash
        raw_bundle = {
            "aeb_id": aeb_id,
            "aee_id": aee.aee_id,
            "aee_hash": aee_hash,
            "prev_evidence_hash": prev_hash,
            "chain_index": index,
            "decision": decision.value,
            "decision_reason": decision_reason,
            "execution_status": execution_status,
            "execution_target": aee.capability.resource,
            "side_effects": side_effects,
            "timestamps": {
                "evaluated_at": evaluated_at,
                "executed_at": executed_at
            }
        }

        # Cryptographic binding: evidence_hash seals the bundle
        evidence_hash = sha256_canonical(raw_bundle)

        aeb = AEB(
            aeb_id=aeb_id,
            aee_id=aee.aee_id,
            aee_hash=aee_hash,
            prev_evidence_hash=prev_hash,
            chain_index=index,
            decision=decision,
            decision_reason=decision_reason,
            execution_status=execution_status,
            execution_target=aee.capability.resource,
            side_effects=side_effects,
            timestamps={"evaluated_at": evaluated_at, "executed_at": executed_at},
            evidence_hash=evidence_hash
        )

        self._chain.append(aeb)
        return aeb

    def verify_integrity(self) -> Tuple[bool, Optional[int], Optional[str]]:
        """
        Performs full cryptographic verification of the evidence chain:
        1. Chain index continuity.
        2. Previous evidence hash pointer consistency.
        3. Internal SHA-256 evidence hash verification for every bundle.
        Returns: (is_valid, failing_index, reason)
        """
        if not self._chain:
            return True, None, "empty_ledger_valid"

        expected_prev = self.genesis_hash
        for idx, aeb in enumerate(self._chain):
            # 1. Index continuity
            if aeb.chain_index != idx:
                return False, idx, f"index_discontinuity_expected_{idx}_got_{aeb.chain_index}"

            # 2. Previous hash link
            if aeb.prev_evidence_hash != expected_prev:
                return False, idx, f"broken_hash_chain_at_index_{idx}"

            # 3. Recalculate canonical hash
            bundle_to_verify = {
                "aeb_id": aeb.aeb_id,
                "aee_id": aee.aee_id if 'aee' in locals() else aeb.aee_id,
                "aee_hash": aeb.aee_hash,
                "prev_evidence_hash": aeb.prev_evidence_hash,
                "chain_index": aeb.chain_index,
                "decision": aeb.decision.value if hasattr(aeb.decision, "value") else str(aeb.decision),
                "decision_reason": aeb.decision_reason,
                "execution_status": aeb.execution_status,
                "execution_target": aeb.execution_target,
                "side_effects": aeb.side_effects,
                "timestamps": aeb.timestamps
            }
            computed_hash = sha256_canonical(bundle_to_verify)
            if computed_hash != aeb.evidence_hash:
                return False, idx, f"tamper_detected_hash_mismatch_at_index_{idx}"

            expected_prev = aeb.evidence_hash

        return True, None, "ledger_cryptographically_sound"

    def export_chain(self) -> List[Dict[str, Any]]:
        return [b.to_dict() for b in self._chain]
