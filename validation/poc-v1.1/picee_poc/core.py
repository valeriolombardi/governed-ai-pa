from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib
import json


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class AuthorizationRequest:
    action_id: str
    principal: str
    ai_agent: str
    action: str
    resource: str
    purpose: str
    delegated_by: str
    capability: str
    expires_at: str
    policy_id: str
    policy_version: str
    approval_id: str | None = None


@dataclass(frozen=True)
class AEE:
    action_id: str
    action: str
    policy_id: str
    policy_version: str
    principal: str
    ai_agent: str
    capability: str
    resource: str
    purpose: str
    delegated_by: str
    expires_at: str
    approval_id: str | None = None

    def to_dict(self):
        return asdict(self)


def _decision_checks(req: AuthorizationRequest, expected: dict, at_time: str):
    return [
        (req.principal == expected["principal"], "principal_not_allowed"),
        (req.ai_agent == expected["ai_agent"], "ai_agent_not_allowed"),
        (req.action == expected["action"], "action_not_allowed"),
        (req.resource == expected["resource"], "resource_not_allowed"),
        (req.purpose == expected["purpose"], "purpose_not_allowed"),
        (req.delegated_by == expected["delegated_by"], "delegation_not_allowed"),
        (req.capability == expected["capability"], "capability_not_granted"),
        (req.policy_id == expected["policy_id"], "policy_not_allowed"),
        (req.policy_version == expected["policy_version"], "stale_policy_version"),
        (parse_time(req.expires_at) > parse_time(at_time), "capability_expired"),
    ]


def strong_baseline_authorize(req: AuthorizationRequest, expected: dict, at_time: str):
    """Cedar-like PARC + OPA-like structured context baseline.

    Deliberately uses the same semantic inputs as PICEE-PA so the comparison
    does not rely on a weak baseline. It returns a normal authorization
    decision and an ordinary audit event.
    """
    for ok, reason in _decision_checks(req, expected, at_time):
        if not ok:
            return False, reason
    return True, "allowed"


def run_strong_baseline(req: AuthorizationRequest, expected: dict, at_time: str, execution_target: str | None = None):
    ok, reason = strong_baseline_authorize(req, expected, at_time)
    target = execution_target if execution_target is not None else req.resource
    audit = {
        "action_id": req.action_id,
        "decision": "ALLOW" if ok else "DENY",
        "decision_reason": reason,
        "request": asdict(req),
        "execution_target": target,
        "execution_status": "executed" if ok else "blocked",
        "executed_at": at_time,
    }
    return audit


def request_to_aee(req: AuthorizationRequest):
    return AEE(
        action_id=req.action_id,
        action=req.action,
        policy_id=req.policy_id,
        policy_version=req.policy_version,
        principal=req.principal,
        ai_agent=req.ai_agent,
        capability=req.capability,
        resource=req.resource,
        purpose=req.purpose,
        delegated_by=req.delegated_by,
        expires_at=req.expires_at,
        approval_id=req.approval_id,
    )


def picee_authorize(aee: AEE, expected: dict, at_time: str):
    req = AuthorizationRequest(
        action_id=aee.action_id,
        principal=aee.principal,
        ai_agent=aee.ai_agent,
        action=aee.action,
        resource=aee.resource,
        purpose=aee.purpose,
        delegated_by=aee.delegated_by,
        capability=aee.capability,
        expires_at=aee.expires_at,
        policy_id=aee.policy_id,
        policy_version=aee.policy_version,
        approval_id=aee.approval_id,
    )
    for ok, reason in _decision_checks(req, expected, at_time):
        if not ok:
            return False, reason
    return True, "allowed"


def run_picee(req: AuthorizationRequest, expected: dict, at_time: str):
    aee = request_to_aee(req)
    ok, reason = picee_authorize(aee, expected, at_time)
    aee_dict = aee.to_dict()
    evidence = {
        "action_id": req.action_id,
        "decision": "ALLOW" if ok else "DENY",
        "decision_reason": reason,
        "execution_status": "executed" if ok else "blocked",
        "execution_target": req.resource,
        "executed_at": at_time,
        "aee_hash": sha256(aee_dict),
        "aee": aee_dict,
    }
    evidence["evidence_hash"] = sha256(evidence)
    return evidence
