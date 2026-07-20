"""Injection-reachability fusion: escalate an ML injection finding only when its
surface can reach an actionable sink, and never otherwise."""
from pathlib import Path

from attestral.injection_reach import annotate_injection_reach
from attestral.ingest import build_model
from attestral.ml import MLConfig
from attestral.ml import scan as ml_scan
from attestral.model import Severity

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _ml(fixture: str):
    model = build_model(str(EXAMPLES / fixture))
    findings, _ = ml_scan(model, MLConfig(engine="heuristic"))
    return model, findings


def test_injectable_tool_reaching_secret_and_egress_is_escalated_with_its_chain():
    model, findings = _ml("injection-reach-demo")
    tool = next(f for f in findings if f.component_id == "mcp_server.summarizer")
    assert tool.severity is Severity.HIGH  # pre-escalation ML band

    notes = annotate_injection_reach(model, findings)
    assert notes and "raised" in notes[0]
    assert tool.severity is Severity.CRITICAL
    assert tool.escalated_from == "high"
    # the witness names both reachable sinks: the secret store and the egress.
    assert "database" in tool.reachability and "network egress" in tool.reachability
    assert tool.reachability_role == "injection-source"


def test_poisoned_system_prompt_reaches_through_the_runtime_it_steers():
    # A language surface that is not a tool grant still steers its agent runtime,
    # so its reach is the union of the runtime's tool surfaces' reach.
    model, findings = _ml("injection-reach-demo")
    prompt = next(f for f in findings if f.component_id == "agent_instruction.CLAUDE")
    annotate_injection_reach(model, findings)
    assert prompt.severity is Severity.CRITICAL
    assert "database" in prompt.reachability and "network egress" in prompt.reachability


def test_injectable_dead_end_reaches_nothing_and_is_not_escalated():
    # split-tool-poisoning: a lone injectable server with no sink to reach.
    model, findings = _ml("split-tool-poisoning")
    before = [f.severity for f in findings]
    notes = annotate_injection_reach(model, findings)
    assert notes == []
    assert [f.severity for f in findings] == before
    assert all(not f.reachability for f in findings)


def test_pass_is_idempotent_and_does_not_double_escalate():
    model, findings = _ml("injection-reach-demo")
    annotate_injection_reach(model, findings)
    after_first = [(f.component_id, f.severity) for f in findings]
    annotate_injection_reach(model, findings)  # second pass must be a no-op
    assert [(f.component_id, f.severity) for f in findings] == after_first


def test_only_ml_findings_are_touched():
    # A deterministic finding on a reachable surface is left to reachability.py;
    # this pass only escalates language surfaces (origin="ml").
    model, findings = _ml("injection-reach-demo")
    from attestral.rules import RuleEngine

    det = [f for f in RuleEngine().evaluate(model) if f.origin == "deterministic"]
    annotate_injection_reach(model, det)
    assert all(not f.reachability for f in det)
