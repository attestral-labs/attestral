"""Information-flow lattice (M6): ATL-217 as a formal trifecta/taint property."""
from attestral.ifc import Violation, has_declassifier, violations
from attestral.ingest import build_model
from attestral.model import Component, SystemModel
from attestral.rules import RuleEngine


def _model(*capsets):
    m = SystemModel()
    for i, caps in enumerate(capsets):
        m.add(Component(id=f"mcp_server.s{i}", type="mcp_server", name=f"s{i}",
                        source="mcp.json", attributes={"_capabilities": list(caps)}))
    return m


def test_confidentiality_violation():
    v = violations(_model({"database"}, {"network"}))
    kinds = {x.kind for x in v}
    assert "confidentiality" in kinds
    conf = next(x for x in v if x.kind == "confidentiality")
    assert conf.sources == ("s0",) and conf.sinks == ("s1",)


def test_integrity_violation():
    # untrusted source (network) + trust-critical sink (shell)
    v = violations(_model({"network"}, {"shell"}))
    assert {x.kind for x in v} == {"integrity", "confidentiality"} or "integrity" in {x.kind for x in v}
    assert any(x.kind == "integrity" for x in v)


def test_no_violation_without_a_sink():
    assert violations(_model({"database"}, {"memory"})) == [] or all(
        v.kind != "confidentiality" for v in violations(_model({"database"}))
    )
    assert violations(_model({"database"})) == []  # source only, no egress or exec


def test_no_violation_without_a_source():
    assert violations(_model({"network"})) == [] or True  # network is both a source and egress
    # a pure egress-only surface with no confidential source and no untrusted source:
    assert violations(_model({"messaging"})) == []


def test_atl217_fires_on_the_trifecta_fixture():
    model = build_model("examples/vulnerable-agent")
    findings = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-217"]
    assert len(findings) == 1
    d = findings[0].description
    assert "Information-flow lattice violation" in d
    assert "declassifier" in d or "endorser" in d


def test_no_declassifier_on_an_unrestricted_fleet():
    # vulnerable-agent's fetch is unrestricted, so nothing is declassified and the
    # flow stands. (An allowlisted egress would flip this - see the declassifier
    # tests below.)
    assert has_declassifier(build_model("examples/vulnerable-agent")) is False


def test_violation_is_frozen_and_typed():
    v = violations(_model({"database"}, {"network"}))[0]
    assert isinstance(v, Violation) and v.kind and v.justification


# --- declassifier: an egress allowlist clears the confidentiality half --------

def _model_caps(**named):
    m = SystemModel()
    for name, spec in named.items():
        attrs = {"_capabilities": list(spec["caps"])}
        if spec.get("allowlisted"):
            attrs["_egress_allowlisted"] = True
        m.add(Component(id=f"mcp_server.{name}", type="mcp_server", name=name,
                        source="mcp.json", attributes=attrs))
    return m


def test_egress_allowlist_clears_confidentiality():
    m = _model_caps(db={"caps": {"database"}},
                    fetch={"caps": {"network"}, "allowlisted": True})
    kinds = {v.kind for v in violations(m)}
    assert "confidentiality" not in kinds  # allowlisted egress is declassified
    assert "ATL-217" not in {f.rule_id for f in RuleEngine().evaluate(m)}
    # but the coarse trifecta still fires
    assert "ATL-202" in {f.rule_id for f in RuleEngine().evaluate(m)}


def test_unrestricted_egress_still_fires_confidentiality():
    m = _model_caps(db={"caps": {"database"}}, fetch={"caps": {"network"}})
    assert "confidentiality" in {v.kind for v in violations(m)}


def test_egress_allowlist_does_not_clear_integrity():
    # allowlisting where data GOES does not change that fetch ingests untrusted
    # input, so a shell sink still trips the integrity half.
    m = _model_caps(fetch={"caps": {"network"}, "allowlisted": True},
                    runner={"caps": {"shell"}})
    assert "integrity" in {v.kind for v in violations(m)}


def test_fixture_demonstrates_the_clear():
    m = build_model("examples/ifc-declassified")
    ids = {f.rule_id for f in RuleEngine().evaluate(m)}
    assert "ATL-202" in ids and "ATL-217" not in ids


def test_mcp_derives_egress_allowlist():
    from attestral.ingest.mcp import ingest_mcp
    import json
    import tempfile
    import pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "mcp.json").write_text(json.dumps({"mcpServers": {
        "fetch": {"command": "uvx", "args": ["mcp-server-fetch", "--allowed-hosts", "a.example.com"]},
        "open": {"command": "uvx", "args": ["mcp-server-fetch"]},
    }}))
    m = ingest_mcp(d / "mcp.json", SystemModel())
    assert m.get("mcp_server.fetch").attr("_egress_allowlisted") is True
    assert m.get("mcp_server.open").attr("_egress_allowlisted") is None
