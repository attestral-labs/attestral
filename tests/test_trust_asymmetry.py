"""Trust-asymmetry escalation: raise a tool-name collision one band when a
lower-trust server can shadow a trusted tool, and never on a symmetric one."""
import json
from pathlib import Path

from attestral.ingest import build_model
from attestral.model import Severity
from attestral.rules import RuleEngine
from attestral.trust_asymmetry import annotate_trust_asymmetry

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _findings(fixture_dir: str):
    # Not the shared findings_for: this also runs the trust-asymmetry pass and
    # returns its notes alongside the (mutated) findings.
    model = build_model(fixture_dir)
    findings = RuleEngine().evaluate(model)
    notes = annotate_trust_asymmetry(model, findings)
    return findings, notes


def _collision(findings):
    return next(f for f in findings if f.rule_id in ("ATL-204", "ATL-219"))


def test_asymmetric_collision_is_raised_and_names_the_shadower():
    findings, notes = _findings(str(EXAMPLES / "tool-shadowing-trust"))
    f = _collision(findings)
    assert f.severity is Severity.CRITICAL
    assert f.escalated_from == "high"
    assert notes and "trust-asymmetry" in notes[0]
    assert "notes-helper" in f.description and "mutable @latest pin" in f.description


def test_symmetric_collision_is_left_alone():
    # both servers pinned: a collision, but not a trust asymmetry.
    findings, notes = _findings(str(EXAMPLES / "tool-shadowing"))
    f = _collision(findings)
    assert f.severity is Severity.HIGH
    assert f.escalated_from == ""
    assert notes == []


def test_confusable_collision_between_pinned_servers_is_not_escalated():
    findings, notes = _findings(str(EXAMPLES / "tool-shadowing-confusable"))
    f = _collision(findings)  # ATL-219
    assert f.severity is Severity.HIGH
    assert notes == []


def test_pass_is_idempotent():
    model = build_model(str(EXAMPLES / "tool-shadowing-trust"))
    findings = RuleEngine().evaluate(model)
    annotate_trust_asymmetry(model, findings)
    snapshot = [(f.rule_id, f.severity, f.description) for f in findings]
    second = annotate_trust_asymmetry(model, findings)  # no-op
    assert second == []
    assert [(f.rule_id, f.severity, f.description) for f in findings] == snapshot


def test_only_collision_rules_are_touched(tmp_path):
    # A lower-trust server on its own (no collision) is never escalated by this
    # pass - it needs a collision finding to act on.
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {
        "solo": {"command": "npx", "args": ["solo-mcp@latest"],
                 "tools": [{"name": "do_thing"}]},
    }}))
    model = build_model(str(tmp_path))
    findings = RuleEngine().evaluate(model)
    before = [(f.rule_id, f.severity) for f in findings]
    assert annotate_trust_asymmetry(model, findings) == []
    assert [(f.rule_id, f.severity) for f in findings] == before
