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


# --- DRF-012: the standing key never actually left ---------------------------

def test_stale_key_fixture_fires_drf_012():
    findings = detect_drift(_policy(), load_events(f"{FIXTURE}/runtime-events-stale-key.jsonl"))
    assert [f.rule_id for f in findings] == ["DRF-012"]
    assert "GITHUB_TOKEN" in findings[0].description


def test_drf_012_fires_alongside_a_live_bypass():
    # brokered=false AND the raw key still present: two distinct facts, two findings.
    ev = {"server": "github", "brokered": False, "env_secrets": ["GITHUB_TOKEN"]}
    ids = [f.rule_id for f in detect_drift(_policy(), [ev])]
    assert sorted(ids) == ["DRF-011", "DRF-012"]


def test_absent_env_secrets_never_fires():
    # Unknown telemetry: an event with no env_secrets key must not fire (the
    # benign stream also proves this end-to-end).
    findings = detect_drift(_policy_with_broker(), [{"server": "gh", "brokered": True}])
    assert "DRF-012" not in {f.rule_id for f in findings}


def test_positively_clean_env_never_fires():
    # An EMPTY list is a positively-observed credential-free environment.
    findings = detect_drift(_policy_with_broker(),
                            [{"server": "gh", "env_secrets": []}])
    assert "DRF-012" not in {f.rule_id for f in findings}


def test_malformed_env_secrets_never_fires():
    # Fail closed on every shape that is not a list of names.
    for bad in ("GITHUB_TOKEN", {"GITHUB_TOKEN": True}, [1, 2], True):
        findings = detect_drift(_policy_with_broker(),
                                [{"server": "gh", "env_secrets": bad}])
        assert "DRF-012" not in {f.rule_id for f in findings}, bad


def test_forbid_env_secrets_constraint_also_expects_a_clean_env():
    # The other half of the policy's credential expectations: compile emits
    # forbid_env_secrets for a secret-holding server; the proxy is supposed to
    # strip at spawn. A runtime report of a still-present key is the same drift.
    policy = {"servers": {"crm": {
        "allow": True, "constraints": {"forbid_env_secrets": True}}}}
    findings = detect_drift(policy, [{"server": "crm", "env_secrets": ["STRIPE_KEY"]}])
    assert [f.rule_id for f in findings] == ["DRF-012"]
    assert "strips env secrets" in findings[0].description


def test_a_server_with_no_credential_expectation_never_fires():
    # No broker_required, no forbid_env_secrets: the policy made no claim about
    # this env, so a reported key is not drift (ATL-104 owns the static side).
    policy = {"servers": {"plain": {"allow": True, "constraints": {}}}}
    findings = detect_drift(policy, [{"server": "plain", "env_secrets": ["X_TOKEN"]}])
    assert not findings


def test_drf_012_is_high_and_quarantines_as_a_narrowing():
    from attestral.drift import remediate_drift
    from attestral.model import Severity
    policy = _policy()
    findings = detect_drift(policy, load_events(f"{FIXTURE}/runtime-events-stale-key.jsonl"))
    assert findings[0].severity is Severity.HIGH
    tightened, delta = remediate_drift(policy, findings)
    assert delta and delta[0]["action"] == "quarantine"
    assert tightened["servers"]["github"]["allow"] is False
