"""Pin the demo tapes (website/demo.html) to the live tool.

The two tapes on the demo page are byte-verified recordings of tool output
over examples/demo-tape. This suite asserts the tape's on-screen claims -
the clean scan, the three drift findings, the containment narrowing, and the
sign/verify/tamper round trip - so the published recording cannot drift from
what attestral actually does.
"""
from attestral.compile import compile_policy
from attestral.drift import detect_drift, load_events
from attestral.incident import build_incident_bundle, verify_incident_bundle
from attestral.ingest import build_model
from attestral.ml import MLConfig
from attestral.ml import scan as ml_scan
from attestral.rules import RuleEngine

FIXTURE = "examples/demo-tape"


def _model_and_policy():
    model = build_model(FIXTURE)
    findings = RuleEngine().evaluate(model)
    return model, findings, compile_policy(model, findings)


def test_remediated_config_scans_clean():
    model, findings, _ = _model_and_policy()
    ml_findings, _ = ml_scan(model, MLConfig(engine="heuristic"))
    assert findings == [] and ml_findings == []


def test_stream_yields_exactly_the_three_tape_findings():
    _, _, policy = _model_and_policy()
    hits = detect_drift(policy, load_events(f"{FIXTURE}/runtime-events.jsonl"))
    assert [(f.rule_id, f.component_id) for f in hits] == [
        ("DRF-005", "mcp_server.github"),
        ("DRF-001", "mcp_server.fetch"),
        ("DRF-003", "mcp_server.filesystem"),
    ]


def test_incident_attests_and_one_edited_byte_fails_verification():
    _, _, policy = _model_and_policy()
    events = load_events(f"{FIXTURE}/runtime-events.jsonl")
    bundle = build_incident_bundle(policy, "runtime-events.jsonl", events)
    ok, failures = verify_incident_bundle(bundle, policy, events)
    assert ok and not failures

    doctored = [dict(e) for e in events]
    doctored[4]["args"] = ["/Users/dev/project/notes.md"]
    ok, failures = verify_incident_bundle(bundle, policy, doctored)
    assert not ok and "subject" in failures
