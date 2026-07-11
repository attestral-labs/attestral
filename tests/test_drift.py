from attestral.compile import compile_policy
from attestral.drift import detect_drift, load_events
from attestral.ingest import build_model
from attestral.rules import RuleEngine


def _drift():
    model = build_model("examples/demo-project")
    policy = compile_policy(model, RuleEngine().evaluate(model))
    return detect_drift(policy, load_events("examples/demo-project/runtime-events.jsonl"))


def test_clean_event_produces_no_drift():
    ids = [(f.rule_id, f.component_id) for f in _drift()]
    assert ("DRF-003", "mcp_server.docs") in ids  # /etc/passwd flagged
    in_scope = [f for f in _drift() if "design.md" in f.description]
    assert not in_scope  # /srv/docs/design.md is fine


def test_out_of_scope_path_detected():
    assert any(f.rule_id == "DRF-003" for f in _drift())


def test_denied_server_invocation_detected():
    hits = [f for f in _drift() if f.rule_id == "DRF-002"]
    assert hits and hits[0].component_id == "mcp_server.shell"


def test_unattested_server_detected():
    hits = [f for f in _drift() if f.rule_id == "DRF-001"]
    assert hits and hits[0].component_id == "mcp_server.jira-sync"


def test_sorted_by_severity():
    ranks = [f.severity.rank for f in _drift()]
    assert ranks == sorted(ranks, reverse=True)
