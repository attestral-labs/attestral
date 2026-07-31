"""The interactive HTML threat topography (`scan --format html`).

Verifies the exporter builds the right data from the model and emits one
self-contained, offline HTML file - no external requests, injection-safe.
"""
import re

from click.testing import CliRunner

from attestral.cli import main
from attestral.ingest import build_model
from attestral.model import Component, Finding, Severity, SystemModel
from attestral.rules import RuleEngine
from attestral.topography import build_topography, render_topography

FIXTURE = "examples/agentic-risks"


def test_build_topography_shapes_surfaces_and_splits_fleet_findings():
    model = build_model(FIXTURE)
    findings = RuleEngine().evaluate(model)
    data = build_topography(model, findings)

    # every component becomes a surface carrying a blast score and reach map
    assert len(data["components"]) == len(model.components)
    ops = next(c for c in data["components"] if c["id"] == "mcp_server.ops")
    assert ops["score"] > 0 and isinstance(ops["reached"], dict)

    # model-scoped findings (the lethal trifecta) land in the fleet bucket, not
    # on any single surface
    per_comp_rules = {f["rule"] for f in data["findings"]}
    fleet_rules = {f["rule"] for f in data["fleet"]}
    assert "ATL-202" in fleet_rules
    assert "ATL-202" not in per_comp_rules
    # the impact rail lists only capability classes some surface actually reaches
    assert data["sinks"] and all(s["k"] for s in data["sinks"])


def test_render_is_self_contained_offline_html():
    model = build_model(FIXTURE)
    findings = RuleEngine().evaluate(model)
    doc = render_topography(model, findings, FIXTURE)

    assert doc.startswith("<!doctype html>")
    assert "__DATA__" not in doc and "__SUB__" not in doc
    # no external resource is ever fetched: no src=/href= to any host, and the
    # only http(s) URL is the SVG XML namespace (not a network load)
    assert not re.search(r'(src|href)\s*=\s*["\']https?://', doc)
    for url in re.findall(r'https?://[^\s"\'<>]+', doc):
        assert url == "http://www.w3.org/2000/svg", url


def test_render_embeds_the_scanned_findings_and_scores():
    model = build_model(FIXTURE)
    findings = RuleEngine().evaluate(model)
    doc = render_topography(model, findings, FIXTURE)
    assert "mcp_server.ops" in doc
    assert "ATL-202" in doc                     # the fleet trifecta callout
    assert FIXTURE in doc


def test_component_name_cannot_break_out_of_the_script():
    # A poisoned config could name a server `</script>...`; the payload must
    # escape < so it can never terminate the script element.
    model = SystemModel()
    model.add(Component(id="mcp_server.x", type="mcp_server",
                        name="</script><img src=x>", source="mcp.json",
                        attributes={"_capabilities": ["shell"]},
                        trust_boundary="agent_runtime"))
    doc = render_topography(model, [], "poisoned")
    assert "</script><img" not in doc
    assert "\\u003c/script\\u003e" in doc


def test_cli_scan_format_html_writes_a_file(tmp_path):
    out = tmp_path / "topo"
    r = CliRunner().invoke(main, ["scan", FIXTURE, "--format", "html", "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "topo.html").exists()
    assert "interactive threat topography" in r.output


def test_no_file_written_without_output_flag():
    # Terminal-first invariant: a plain scan writes nothing.
    r = CliRunner().invoke(main, ["scan", FIXTURE])
    assert r.exit_code == 0
    assert "no files written" in r.output


def test_render_handles_a_model_with_no_findings():
    model = SystemModel()
    model.add(Component(id="mcp_server.solo", type="mcp_server", name="solo",
                        source="mcp.json", attributes={"_capabilities": []},
                        trust_boundary="agent_runtime"))
    doc = render_topography(model, [], "solo-project")
    assert doc.startswith("<!doctype html>")
    assert "solo" in doc


def test_severity_is_rendered_as_a_lowercase_class():
    # Severity is part of the finding contract the exporter reads; a hand-built
    # finding must render its severity name so the view can colour it.
    model = SystemModel()
    model.add(Component(id="mcp_server.a", type="mcp_server", name="a",
                        source="mcp.json", attributes={"_capabilities": ["shell"]},
                        trust_boundary="agent_runtime"))
    f = Finding(rule_id="ATL-103", title="Shell server", severity=Severity.CRITICAL,
                component_id="mcp_server.a", description="d", recommendation="r")
    doc = render_topography(model, [f], "p")
    assert "ATL-103" in doc and "critical" in doc
