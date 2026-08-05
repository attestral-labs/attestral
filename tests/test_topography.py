"""The interactive HTML threat topography (`scan --format html`).

Verifies the exporter builds the right data from the model - trust-boundary
zones, modeled edges, walked attack paths - and emits one self-contained,
offline HTML file - no external requests, injection-safe.
"""
import re

from click.testing import CliRunner

from attestral import topography
from attestral.cli import main
from attestral.ingest import build_model
from attestral.model import Component, Edge, Finding, Severity, SystemModel
from attestral.rules import RuleEngine
from attestral.topography import build_topography, render_topography

FIXTURE = "examples/agentic-risks"
CLOUD_AGENT_FIXTURE = "examples/demo-project"    # terraform + mcp.json in one design
PATH_FIXTURE = "examples/attack-path"            # walks an external and an internal chain


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
    # escape < so it can never terminate the script element. The hostile name
    # flows through every new payload field too (edges reference its id), so
    # the whole payload rides the same escaping.
    model = SystemModel()
    model.add(Component(id="mcp_server.x", type="mcp_server",
                        name="</script><img src=x>", source="mcp.json",
                        attributes={"_capabilities": ["shell"]},
                        trust_boundary="agent_runtime"))
    model.add(Component(id="aws_s3_bucket.data", type="aws_s3_bucket", name="data",
                        source="main.tf", trust_boundary="cloud"))
    model.edges.append(Edge("mcp_server.x", "aws_s3_bucket.data", kind="tool_access"))
    doc = render_topography(model, [], "poisoned")
    assert "</script><img" not in doc
    assert "\\u003c/script\\u003e" in doc
    assert '"edges":[{"s":"mcp_server.x","t":"aws_s3_bucket.data","cross":true}]' in doc


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


# ---------------------------------------------------------------------------
# v2: trust-boundary zones, modeled edges, walked attack paths.
# ---------------------------------------------------------------------------

def _mini_cross_boundary_model():
    model = SystemModel()
    model.add(Component(id="mcp_server.agent", type="mcp_server", name="agent",
                        source="mcp.json", attributes={"_capabilities": ["shell"]},
                        trust_boundary="agent_runtime"))
    model.add(Component(id="mcp_server.helper", type="mcp_server", name="helper",
                        source="mcp.json", attributes={"_capabilities": []},
                        trust_boundary="agent_runtime"))
    model.add(Component(id="aws_s3_bucket.data", type="aws_s3_bucket", name="data",
                        source="main.tf", trust_boundary="cloud"))
    model.edges.append(Edge("mcp_server.agent", "aws_s3_bucket.data", kind="tool_access"))
    model.edges.append(Edge("mcp_server.agent", "mcp_server.helper"))
    # A taint sentinel has no rendered node, so this edge must be dropped.
    model.edges.append(Edge("mcp_server.agent", "taint:untrusted_input", kind="taint_source"))
    return model


def test_edges_carry_cross_boundary_flags_and_drop_sentinels():
    data = build_topography(_mini_cross_boundary_model(), [])
    assert data["edges"] == [
        {"s": "mcp_server.agent", "t": "aws_s3_bucket.data", "cross": True},
        {"s": "mcp_server.agent", "t": "mcp_server.helper", "cross": False},
    ]


def test_zones_render_only_present_boundaries():
    # A terraform + mcp design produces both zones, agent_runtime first.
    model = build_model(CLOUD_AGENT_FIXTURE)
    data = build_topography(model, [])
    assert [z["k"] for z in data["zones"]] == ["agent_runtime", "cloud"]
    assert {c["boundary"] for c in data["components"]} == {"agent_runtime", "cloud"}
    doc = render_topography(model, [], CLOUD_AGENT_FIXTURE)
    assert '"zones":[{"k":"agent_runtime","more":0},{"k":"cloud","more":0}]' in doc


def test_model_with_no_cloud_components_renders_no_cloud_zone():
    model = build_model(FIXTURE)                 # mcp-only design
    data = build_topography(model, [])
    assert [z["k"] for z in data["zones"]] == ["agent_runtime"]
    doc = render_topography(model, [], FIXTURE)
    assert '"zones":[{"k":"agent_runtime","more":0}]' in doc


def test_attack_paths_are_walked_into_the_payload():
    model = build_model(PATH_FIXTURE)
    data = build_topography(model, RuleEngine().evaluate(model))
    kinds = {p["kind"] for p in data["paths"]}
    assert kinds == {"external", "internal"}
    sev = {p["kind"]: p["sev"] for p in data["paths"]}
    assert sev == {"external": "critical", "internal": "high"}
    comp_ids = {c["id"] for c in data["components"]}
    for p in data["paths"]:
        assert p["steps"][0]["role"] == "entry"
        assert p["steps"][-1]["role"] == "impact"
        for s in p["steps"]:
            assert s["id"] in comp_ids            # steps reference rendered nodes only
            assert s["role"] in {"entry", "pivot", "impact"}


def test_zone_cap_overflows_gracefully_and_paths_stay_rendered(monkeypatch):
    # Past the per-zone cap the zone reports "+N more" instead of drawing a
    # hairball, and path steps still reference only the nodes that render.
    monkeypatch.setattr(topography, "_ZONE_CAP", 1)
    model = build_model(PATH_FIXTURE)
    data = build_topography(model, [])
    assert len(data["components"]) == 1
    assert data["zones"] == [{"k": "agent_runtime", "more": 2}]
    comp_ids = {c["id"] for c in data["components"]}
    for p in data["paths"]:
        for s in p["steps"]:
            assert s["id"] in comp_ids


def test_full_render_on_vulnerable_agent_carries_a_walked_chain():
    model = build_model("examples/vulnerable-agent")
    findings = RuleEngine().evaluate(model)
    doc = render_topography(model, findings, "examples/vulnerable-agent")
    assert doc.startswith("<!doctype html>")
    assert '"paths":[]' not in doc
    assert '"kind":"internal"' in doc


def test_full_render_on_cloud_plus_agent_fixture_is_offline_and_deterministic():
    model = build_model(CLOUD_AGENT_FIXTURE)
    findings = RuleEngine().evaluate(model)
    doc = render_topography(model, findings, CLOUD_AGENT_FIXTURE)
    assert doc.startswith("<!doctype html>")
    # still one self-contained file: no external resource loads
    assert not re.search(r'(src|href)\s*=\s*["\']https?://', doc)
    for url in re.findall(r'https?://[^\s"\'<>]+', doc):
        assert url == "http://www.w3.org/2000/svg", url
    # stable sort orders everywhere: a second render is byte-identical
    assert doc == render_topography(model, findings, CLOUD_AGENT_FIXTURE)


def test_cross_boundary_reach_path_is_a_clickable_overlay():
    # ATL-222's confused-deputy path renders as a named cross-boundary chain:
    # injectable surface -> co-resident deputy -> the NAMED cloud resource. This
    # is the agent->cloud picture no per-file scanner can draw.
    model = build_model("examples/agent-cloud-confused-deputy")
    data = build_topography(model, RuleEngine().evaluate(model))
    xb = [p for p in data["paths"] if p["kind"] == "cross-boundary"]
    assert xb, "expected a cross-boundary reach path"
    steps = xb[0]["steps"]
    assert [s["role"] for s in steps] == ["entry", "deputy", "cloud sink"]
    assert steps[0]["id"] == "mcp_server.web-fetch"
    assert steps[1]["id"] == "mcp_server.aws-deploy"
    assert steps[2]["id"].startswith("aws_")          # a NAMED cloud resource node
    # every step id is a rendered node, so the overlay never points at a gap
    rendered = {c["id"] for c in data["components"]}
    assert all(s["id"] in rendered for s in steps)


def test_cross_boundary_overlay_survives_html_render():
    model = build_model("examples/agent-cloud-confused-deputy")
    doc = render_topography(model, RuleEngine().evaluate(model), "confused-deputy")
    assert "cross-boundary" in doc                      # the overlay is in the payload
    assert "aws_s3_bucket.customer_data" in doc         # the named cloud sink is drawn
    assert "<!doctype html>" in doc.lower()             # one self-contained document
