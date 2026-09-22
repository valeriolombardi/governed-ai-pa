import unittest
from picee_poc.core import AuthorizationRequest, run_strong_baseline, run_picee

NOW = "2026-09-22T09:00:00+00:00"
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

def make_req(**changes):
    data = dict(
        action_id="act-0042", principal="pa-officer-42", ai_agent="agent-case-01",
        action="update_case_record", resource="case/2026/0042",
        purpose="case-administration", delegated_by="director-07",
        capability="case.update", expires_at="2026-09-22T12:00:00+00:00",
        policy_id="PA-CASE-UPDATE", policy_version="7", approval_id="appr-991"
    )
    data.update(changes)
    return AuthorizationRequest(**data)

class TestPicee(unittest.TestCase):
    def assert_case(self, req, expected_reason=None):
        b = run_strong_baseline(req, EXPECTED, NOW)
        p = run_picee(req, EXPECTED, NOW)
        self.assertEqual(b["decision"], p["decision"])
        self.assertEqual(b["decision_reason"], p["decision_reason"])
        if expected_reason:
            self.assertEqual(expected_reason, b["decision_reason"])
        return b, p

    def test_authorized(self):
        b, p = self.assert_case(make_req())
        self.assertEqual(b["decision"], "ALLOW")
        self.assertEqual(p["execution_status"], "executed")
        self.assertTrue(p["aee_hash"])
        self.assertTrue(p["evidence_hash"])

    def test_wrong_principal(self):
        self.assert_case(make_req(principal="pa-officer-99"), "principal_not_allowed")

    def test_wrong_agent(self):
        self.assert_case(make_req(ai_agent="agent-case-99"), "ai_agent_not_allowed")

    def test_expired(self):
        self.assert_case(make_req(expires_at="2026-09-22T08:00:00+00:00"), "capability_expired")

    def test_wrong_capability(self):
        self.assert_case(make_req(capability="case.delete"), "capability_not_granted")

    def test_wrong_action(self):
        self.assert_case(make_req(action="delete_case_record"), "action_not_allowed")

    def test_stale_policy(self):
        self.assert_case(make_req(policy_version="6"), "stale_policy_version")

if __name__ == "__main__":
    unittest.main(verbosity=2)
