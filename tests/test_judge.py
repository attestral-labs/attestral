from attestral.evidence import audit_chain
from attestral.judge import (
    JudgeConfig,
    apply_verdict,
    build_context,
    decide,
    judge_findings,
    _parse_verdict,
)
from attestral.model import Component, Finding, Severity, SystemModel


def _model_and_finding():
    m = SystemModel()
    m.add(Component(id="mcp_server.shell", type="mcp_server", name="shell",
                    source="mcp.json", attributes={"command": "bash"},
                    trust_boundary="agent_runtime"))
    f = Finding("ATL-103", "Shell-capable MCP server", Severity.CRITICAL,
                "mcp_server.shell", "d", "r")
    return m, f


def test_build_context_includes_component_attributes():
    m, f = _model_and_finding()
    ctx = build_context(m, f)
    assert ctx["finding"]["rule_id"] == "ATL-103"
    assert ctx["component"]["attributes"]["command"] == "bash"
    assert ctx["component"]["trust_boundary"] == "agent_runtime"


def test_build_context_handles_model_level_finding():
    m, _ = _model_and_finding()
    f = Finding("ATL-201", "cross boundary", Severity.INFO, "model", "d", "r")
    ctx = build_context(m, f)
    assert ctx["component"] is None  # no component named "model"; must not crash


def test_decide_majority_vote():
    votes = [
        {"verdict": "confirmed", "confidence": 0.9, "reasoning": "real"},
        {"verdict": "confirmed", "confidence": 0.7, "reasoning": "also real"},
        {"verdict": "false_positive", "confidence": 0.6, "reasoning": "nope"},
    ]
    verdict, confidence, reasoning = decide(votes)
    assert verdict == "confirmed"
    assert confidence == 0.8            # mean of the two winning votes
    assert reasoning == "real"


def test_apply_verdict_annotates_without_suppressing_by_default():
    _, f = _model_and_finding()
    apply_verdict(f, "false_positive", 0.95, "not exploitable", JudgeConfig(suppress=False))
    assert f.judge_verdict == "false_positive"
    assert f.judge_confidence == 0.95
    assert f.waived is False            # fail-safe: annotate only


def test_apply_verdict_suppresses_confident_false_positive_on_the_record():
    _, f = _model_and_finding()
    apply_verdict(f, "false_positive", 0.95, "sandbox only", JudgeConfig(suppress=True))
    assert f.waived is True
    assert "llm-judge" in f.waiver_reason and "sandbox only" in f.waiver_reason


def test_apply_verdict_does_not_suppress_low_confidence():
    _, f = _model_and_finding()
    apply_verdict(f, "false_positive", 0.4, "maybe", JudgeConfig(suppress=True))
    assert f.waived is False            # below suppress_min_confidence


def test_confirmed_finding_is_never_suppressed():
    _, f = _model_and_finding()
    apply_verdict(f, "confirmed", 0.99, "definitely real", JudgeConfig(suppress=True))
    assert f.waived is False


def test_parse_verdict_tolerates_code_fences_and_rejects_bad_verdicts():
    assert _parse_verdict('```json\n{"verdict":"confirmed","confidence":0.8}\n```')["verdict"] == "confirmed"
    assert _parse_verdict('{"verdict":"banana","confidence":1}') is None
    assert _parse_verdict("not json") is None


def test_verdict_is_recorded_in_the_evidence_chain():
    _, f = _model_and_finding()
    apply_verdict(f, "needs_review", 0.5, "unclear", JudgeConfig())
    chain = audit_chain([f])
    assert chain[0]["finding"]["judge_verdict"] == "needs_review"


def test_judge_findings_skips_cleanly_without_a_key(monkeypatch):
    monkeypatch.delenv("ATTESTRAL_JUDGE_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    m, f = _model_and_finding()
    notes = judge_findings(m, [f], JudgeConfig())
    assert notes and "judge skipped" in notes[0]
    assert f.judge_verdict == ""        # nothing changed
