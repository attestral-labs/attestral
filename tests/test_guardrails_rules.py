"""Coverage for the guardrails coverage wave: ATL-124 and ATL-212.

Rails constrain the dialog channel; the tool fleet acts outside them. ATL-124
flags a rails config that validates input but never output, and ATL-212 flags
the fleet-level contradiction: a railed dialog beside an auto-approved
shell-capable tool that no rail can see. Both sides of that pairing live in
files that know nothing of each other - only the system model holds both.
"""
import pytest

from attestral.ingest import build_model
from attestral.ingest.agent_config import ingest_agent_config
from attestral.model import Component, SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/guardrails-gap"


def _findings(model):
    return RuleEngine().evaluate(model)


def _rails_component() -> Component:
    """A unit-built guardrails_config matching the ingester's contract."""
    return Component(
        id="guardrails_config.assistant",
        type="guardrails_config",
        name="assistant",
        source="assistant/config.yml",
        attributes={
            "_input_rails": ["self check input"],
            "_output_rails": [],
            "_has_input_rails": True,
            "_has_output_rails": False,
            "_output_unrailed": True,
            "_colang_files": 1,
            "engines": ["openai"],
        },
        trust_boundary="agent_runtime",
    )


def _shell_component(ctype: str = "mcp_server", auto_approve: bool = True) -> Component:
    return Component(
        id=f"{ctype}.ops",
        type=ctype,
        name="ops",
        source="mcp.json",
        attributes={"_capabilities": ["shell"], "_auto_approve": auto_approve},
        trust_boundary="agent_runtime",
    )


def test_output_unrailed_fires_atl124():
    model = build_model(FIXTURE)
    hits = [f for f in _findings(model) if f.rule_id == "ATL-124"]
    assert len(hits) == 1
    assert hits[0].component_id == "guardrails_config.guardrails"


def test_railed_dialog_unrailed_execution_fires_atl212():
    model = build_model(FIXTURE)
    hits = [f for f in _findings(model) if f.rule_id == "ATL-212"]
    assert len(hits) == 1
    f = hits[0]
    # Attributed to the execution tool, with the detail naming BOTH sides.
    assert f.component_id == "mcp_server.shell"
    assert "[guardrails]" in f.description
    assert "'shell'" in f.description


def test_fixture_fires_exactly_the_intended_findings():
    # The README owner pins this: guardrails-gap goes 2 -> 4 findings.
    model = build_model(FIXTURE)
    ids = sorted(f.rule_id for f in _findings(model))
    assert ids == ["ATL-103", "ATL-108", "ATL-124", "ATL-212"]


def test_rails_without_auto_approved_shell_do_not_fire_atl212():
    # Unit-built single-sided model: rails alone are not a contradiction.
    model = SystemModel()
    model.add(_rails_component())
    ids = {f.rule_id for f in _findings(model)}
    assert "ATL-212" not in ids
    assert "ATL-124" in ids  # the input-only config itself still flags


def test_auto_approved_shell_without_rails_does_not_fire_atl212():
    # Unit-built single-sided model: an ungated shell tool alone is
    # ATL-103/108's job, not a rails contradiction.
    model = SystemModel()
    model.add(_shell_component())
    assert "ATL-212" not in {f.rule_id for f in _findings(model)}


def test_vulnerable_agent_fixture_has_no_rails_so_no_atl212():
    # examples/vulnerable-agent is exactly the shell-without-rails case:
    # ATL-108 proves the auto-approved shell side exists, yet with no
    # guardrails_config in the model ATL-212 must stay silent.
    model = build_model("examples/vulnerable-agent")
    assert model.by_type("guardrails_config") == []
    ids = {f.rule_id for f in _findings(model)}
    assert "ATL-108" in ids
    assert "ATL-212" not in ids


def test_rails_with_unapproved_shell_do_not_fire_atl212():
    # Shell capability WITH a human checkpoint is the recommended end state;
    # it must not fire.
    model = SystemModel()
    model.add(_rails_component())
    model.add(_shell_component(auto_approve=False))
    assert "ATL-212" not in {f.rule_id for f in _findings(model)}


def test_shell_capable_subagent_counts_as_execution_side():
    # The execution side is the capability union: an auto-approved
    # shell-capable subagent contradicts the rails exactly like a server.
    model = SystemModel()
    model.add(_rails_component())
    model.add(_shell_component(ctype="subagent"))
    hits = [f for f in _findings(model) if f.rule_id == "ATL-212"]
    assert len(hits) == 1
    assert hits[0].component_id == "subagent.ops"
    assert "[assistant]" in hits[0].description


def test_one_finding_per_offending_execution_component():
    model = SystemModel()
    model.add(_rails_component())
    a = _shell_component()
    b = _shell_component()
    b.id, b.name = "mcp_server.deploy", "deploy"
    model.add(a)
    model.add(b)
    hits = [f for f in _findings(model) if f.rule_id == "ATL-212"]
    assert sorted(f.component_id for f in hits) == [
        "mcp_server.deploy", "mcp_server.ops",
    ]


def test_fully_railed_config_does_not_fire_atl124(tmp_path):
    d = tmp_path / "assistant"
    d.mkdir()
    (d / "config.yml").write_text(
        "colang_version: \"1.0\"\n"
        "rails:\n"
        "  input:\n"
        "    flows:\n"
        "      - self check input\n"
        "  output:\n"
        "    flows:\n"
        "      - self check output\n"
    )
    model = ingest_agent_config(tmp_path, SystemModel())
    assert len(model.by_type("guardrails_config")) == 1
    assert "ATL-124" not in {f.rule_id for f in _findings(model)}


@pytest.mark.parametrize("spec", ['"true"', "{ enabled: true }", "[true]"])
def test_malformed_matcher_spec_fails_closed(tmp_path, spec):
    # The model has both sides (rails + auto-approved shell), so a valid spec
    # WOULD fire - a malformed one (string, dict, list) must return nothing.
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: X-9\n    title: bad\n    severity: high\n    target: model\n"
        f"    match: {{ model_railed_dialog_unrailed_execution: {spec} }}\n"
    )
    model = build_model(FIXTURE)
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}
    assert "X-9" not in ids
    assert "ATL-212" in ids  # the well-formed builtin still fires on the same model
