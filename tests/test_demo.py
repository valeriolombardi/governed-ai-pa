import sys, pathlib
sys.path.insert(0,str(pathlib.Path(__file__).parents[1]/"src"))
from picee_pa_demo import evaluate

def base():
    return {"aee_id":"x","purpose":"demo","requester":{"id":"u","type":"human"},"agent":{"id":"a"},"capability":{"action":"case.add_internal_note","resource":"case:x"},"action_class":"L2","approval":{"required":True},"policy":{"id":"p","version":"1"}}

def test_l2_requires_approval():
    assert evaluate(base(),False)[0]=="review"

def test_l2_allows_after_approval():
    assert evaluate(base(),True)[0]=="allow"

def test_unknown_capability_denied():
    x=base(); x["capability"]["action"]="system.delete_everything"
    assert evaluate(x,True)[0]=="deny"
