"""DRF-011: the runtime half of CB4A TM-11 (broker bypass).

The static ATL-221 catches a broker declared beside a raw standing credential.
This is its runtime complement: a server the attested design routes through a
credential broker is reached directly at runtime, skipping the broker's auth,
scoping, and audit. The compile -> drift loop is exercised for real, and every
fail-closed non-fire is asserted so the check cannot be widened into a
false-positive machine without a test going red.
"""
from attestral.compile import compile_policy
from attestral.drift import detect_drift, load_events
from attestral.ingest import build_model
from attestral.model import Component, SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/broker-bypass-runtime"


def _policy(path=FIXTURE):
    model = build_model(path)
    return compile_policy(model, RuleEngine().evaluate(model), chain_head="deadbeef")


def test_compile_marks_a_broker_fronted_server():
    policy = _policy()
    assert policy["servers"]["github"].get("broker_required") is True


def test_a_direct_call_to_a_brokered_server_fires_drf_011():
    findings = detect_drift(_policy(), load_events(f"{FIXTURE}/runtime-events-malicious.jsonl"))
    assert [f.rule_id for f in findings] == ["DRF-011"]


def test_a_brokered_call_is_clean():
    findings = detect_drift(_policy(), load_events(f"{FIXTURE}/runtime-events-benign.jsonl"))
    assert "DRF-011" not in {f.rule_id for f in findings}


def _policy_with_broker():
    m = SystemModel()
    m.add(Component(id="mcp_server.gh", type="mcp_server", name="gh", source="m"))
    m.add(Component(id="agentgateway_route.gh", type="agentgateway_route", name="gh", source="g"))
    return compile_policy(m, [], chain_head="x")


def test_absent_brokered_field_never_fires():
    # Unknown telemetry (no `brokered` key) must not fire, exactly as an absent
    # `capabilities` key does not fire DRF-008. Fail-closed.
    findings = detect_drift(_policy_with_broker(), [{"server": "gh"}])
    assert not findings


def test_a_bypass_on_a_non_brokered_server_never_fires():
    # brokered=false on a server the design does NOT route through a broker is not
    # a bypass - there was no broker to bypass. Only a broker_required server fires.
    m = SystemModel()
    m.add(Component(id="mcp_server.plain", type="mcp_server", name="plain", source="m"))
    policy = compile_policy(m, [], chain_head="x")
    assert policy["servers"]["plain"].get("broker_required") is None
    findings = detect_drift(policy, [{"server": "plain", "brokered": False}])
    assert "DRF-011" not in {f.rule_id for f in findings}
