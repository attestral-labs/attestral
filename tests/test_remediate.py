"""M9: structured remediation - the concrete source edit that clears a finding,
derived from the rule matcher and the component's real value."""
from click.testing import CliRunner

from attestral.cli import main
from attestral.ingest import build_model
from attestral.remediate import suggest
from attestral.rules import RuleEngine

FIXTURE = "examples/demo-project"


def _ctx():
    engine = RuleEngine()
    model = build_model(FIXTURE)
    findings = engine.evaluate(model)
    idx = {r["id"]: r for r in engine.rules}
    return model, findings, idx


def _for(findings, idx, rule_id, model):
    f = next(x for x in findings if x.rule_id == rule_id)
    return suggest(model, f, idx.get(rule_id))


def test_boolean_flag_flips():
    model, findings, idx = _ctx()
    s = _for(findings, idx, "ATL-004", model)   # publicly_accessible: true
    assert s.derived
    assert s.attribute == "publicly_accessible"
    assert s.before == "true" and s.after == "false"
    assert s.edit == "set `publicly_accessible = false`"


def test_prefix_transform_http_to_https():
    model, findings, idx = _ctx()
    s = _for(findings, idx, "ATL-101", model)
    assert s.derived
    assert s.before.startswith("http://") and s.after.startswith("https://")


def test_attr_in_lists_the_offending_tokens():
    model, findings, idx = _ctx()
    s = _for(findings, idx, "ATL-001", model)   # acl in [public-read, ...]
    assert s.derived and s.attribute == "acl"
    assert "public-read" in s.edit


def test_derived_underscore_attribute_falls_back_to_recommendation():
    # ATL-002 matches on `_ingress_cidr_blocks` (ingester-derived), so no field edit.
    model, findings, idx = _ctx()
    s = _for(findings, idx, "ATL-002", model)
    assert not s.derived
    assert s.edit == next(f for f in findings if f.rule_id == "ATL-002").recommendation


def test_component_source_file_is_carried():
    model, findings, idx = _ctx()
    s = _for(findings, idx, "ATL-101", model)
    assert s.source.endswith("mcp.json")


def test_model_level_finding_falls_back():
    # A model-level rule (component_id "model") has no single-attribute edit.
    model, findings, idx = _ctx()
    model_f = next((f for f in findings if f.component_id == "model"), None)
    if model_f:                                  # demo-project has one
        s = suggest(model, model_f, idx.get(model_f.rule_id))
        assert not s.derived


# --- CLI --------------------------------------------------------------------

def test_remediate_cli():
    r = CliRunner().invoke(main, ["remediate", FIXTURE])
    assert r.exit_code == 0, r.output
    assert "Remediation" in r.output
    assert "with a concrete edit" in r.output
    assert "set `publicly_accessible = false`" in r.output


def test_remediate_cli_rule_filter_and_unknown():
    r = CliRunner().invoke(main, ["remediate", FIXTURE, "--rule", "atl-101"])
    assert r.exit_code == 0 and "ATL-101" in r.output and "ATL-004" not in r.output
    r = CliRunner().invoke(main, ["remediate", FIXTURE, "--rule", "ATL-999"])
    assert r.exit_code == 1 and "does not fire" in r.output


def test_standing_credential_suggestion_is_the_exact_keys_to_delete():
    # Broker-family findings match ingester-derived attrs, but their edit IS
    # mechanically derivable: the exact env keys to delete, with the generated
    # broker route as the replacement - not a prose fallback.
    engine = RuleEngine()
    model = build_model("examples/vulnerable-agent")
    findings = [f for f in engine.evaluate(model) if f.rule_id == "ATL-104"]
    assert findings
    s = suggest(model, findings[0], next(r for r in engine.rules if r["id"] == "ATL-104"))
    assert s.derived
    assert s.attribute == "env"
    assert "JIRA_API_TOKEN" in s.before
    assert "--broker-output" in s.edit
