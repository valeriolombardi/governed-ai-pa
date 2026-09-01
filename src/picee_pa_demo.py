"""Minimal synthetic PICEE-PA reference implementation. Not production security."""
from __future__ import annotations
import hashlib, json, datetime

def canonical_hash(obj):
    data=json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
    return "sha256:"+hashlib.sha256(data).hexdigest()

def evaluate(aee, approved=False):
    required=["aee_id","purpose","requester","agent","capability","action_class","policy"]
    missing=[k for k in required if k not in aee]
    if missing: return "deny","missing_context"
    if not aee["agent"].get("id"): return "deny","unknown_agent"
    if aee["capability"].get("action") not in {"case.read","case.suggest_route","case.add_internal_note"}:
        return "deny","capability_not_allowed"
    if aee["action_class"]=="L3" and not approved: return "review","human_authorization_required"
    if aee["action_class"]=="L2" and aee.get("approval",{}).get("required") and not approved:
        return "review","approval_required"
    return "allow","policy_satisfied"

def make_aeb(aee, decision, reason, executed=False):
    now=datetime.datetime.now(datetime.timezone.utc).isoformat()
    aeb={"aeb_id":"aeb-"+canonical_hash(aee)[7:19],"aee_id":aee.get("aee_id"),"decision":decision,"reason_code":reason,"execution":{"executed":executed},"timestamps":{"evaluated_at":now},"versions":aee.get("versions",{})}
    aeb["evidence_hash"]=canonical_hash(aeb)
    return aeb

if __name__=="__main__":
    aee=json.load(open("examples/aee.example.json",encoding="utf-8"))
    decision,reason=evaluate(aee,approved=False)
    print(decision,reason)
    decision,reason=evaluate(aee,approved=True)
    print(json.dumps(make_aeb(aee,decision,reason,executed=decision=="allow"),indent=2))
