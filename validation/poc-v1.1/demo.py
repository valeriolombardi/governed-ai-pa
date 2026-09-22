import json
from picee_poc.core import AuthorizationRequest, run_strong_baseline, run_picee

EXPECTED = {
    "principal": "pa-officer-42",
    "ai_agent": "agent-case-01",
    "action": "update_case_record",
    "resource": "case/2026/0042",
    "purpose": "case-administration",
    "delegated_by": "director-07",
    "capability": "case.update",
    "policy_id": "PA-CASE-UPDATE",
    "policy_version": "7",
}

NOW = "2026-09-22T09:00:00+00:00"
REQ = AuthorizationRequest(
    action_id="act-0042",
    principal="pa-officer-42",
    ai_agent="agent-case-01",
    action="update_case_record",
    resource="case/2026/0042",
    purpose="case-administration",
    delegated_by="director-07",
    capability="case.update",
    expires_at="2026-09-22T12:00:00+00:00",
    policy_id="PA-CASE-UPDATE",
    policy_version="7",
    approval_id="appr-991",
)

print("STRONG BASELINE")
print(json.dumps(run_strong_baseline(REQ, EXPECTED, NOW), indent=2))
print("\nPICEE-PA")
print(json.dumps(run_picee(REQ, EXPECTED, NOW), indent=2))
