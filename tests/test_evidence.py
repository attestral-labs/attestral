import json

from attestral.evidence import audit_chain, verify_chain
from attestral.ingest import build_model
from attestral.rules import RuleEngine


def test_chain_verifies():
    model = build_model("examples/demo-project")
    chain = audit_chain(RuleEngine().evaluate(model))
    assert chain and verify_chain(chain)


def test_tampering_detected():
    model = build_model("examples/demo-project")
    chain = audit_chain(RuleEngine().evaluate(model))
    tampered = json.loads(json.dumps(chain))
    tampered[0]["finding"]["severity"] = "info"   # downgrade a finding
    assert not verify_chain(tampered)


def test_empty_chain_is_valid():
    assert verify_chain([])
