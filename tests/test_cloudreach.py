"""ATL-222: the agent-to-cloud confused deputy as a graph property.

An injectable agent surface with no credential of its own, co-resident with a
cloud-credential holder that reaches named Terraform/K8s resources, is a cloud
breach one injection away - and the finding NAMES the reachable resource, which
only the whole system model can do. Every fail-closed non-fire is asserted so the
check cannot be widened into a false-positive machine without a test going red.
"""
from attestral.cloudreach import cross_boundary_reaches
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.model import Component, SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/agent-cloud-confused-deputy"


def _ids(model):
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def _mcp(cfg_json, tmp_path):
    p = tmp_path / "mcp.json"
    p.write_text(cfg_json)
    return ingest_mcp(p, SystemModel())


def test_fixture_fires_atl_222():
    assert "ATL-222" in _ids(build_model(FIXTURE))


def test_finding_names_the_concrete_cloud_sinks():
    model = build_model(FIXTURE)
    f = next(f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-222")
    # the moat: the named IaC resource at the end of the laundered path
    assert "aws_s3_bucket.customer_data" in f.description
    assert "aws_dynamodb_table.sessions" in f.description
    assert "web-fetch" in f.description and "aws-deploy" in f.description
    # the finding attaches to the injectable entry (the actionable component)
    assert f.component_id == "mcp_server.web-fetch"


def test_reach_analysis_shape():
    reaches = cross_boundary_reaches(build_model(FIXTURE))
    assert len(reaches) == 1
    r = reaches[0]
    assert r.entry == "web-fetch" and r.deputy == "aws-deploy"
    assert r.example_path[0] == "web-fetch" and r.example_path[1] == "aws-deploy"
    assert any(s.startswith("aws_s3_bucket.") for s in r.sinks)


def test_no_injectable_entry_does_not_fire():
    # agent-cloud-mesh has the cloud-cred holder but NO co-resident injectable
    # surface - the deputy alone is ATL-112, not a laundered path.
    assert "ATL-222" not in _ids(build_model("examples/agent-cloud-mesh"))


def test_injectable_surface_without_a_deputy_does_not_fire(tmp_path):
    # A fetcher with no co-resident cloud-credential holder reaches no cloud.
    model = _mcp('{"mcpServers": {"web-fetch": {"command": "npx", "args": ["server-fetch"]}}}', tmp_path)
    assert "ATL-222" not in _ids(model)


def test_entry_that_holds_its_own_credential_does_not_fire(tmp_path):
    # If the injectable surface holds the cloud credential ITSELF, it is ATL-112/
    # ATL-115's per-server lane - not a confused deputy across two components.
    model = _mcp(
        '{"mcpServers": {"web-fetch": {"command": "npx", "args": ["server-fetch"], '
        '"env": {"AWS_ACCESS_KEY_ID": "x", "AWS_SECRET_ACCESS_KEY": "y"}}}}',
        tmp_path,
    )
    # add a cloud resource so a reach edge could exist
    model.add(Component(id="aws_s3_bucket.data", type="aws_s3_bucket", name="data",
                        source="t", trust_boundary="cloud"))
    assert "ATL-222" not in _ids(model)


def test_non_injectable_co_resident_does_not_fire():
    # Build a runtime where the co-resident non-deputy holds NO taint capability:
    # a plain server beside the deputy is not an injection entry.
    m = build_model("examples/agent-cloud-mesh")
    # aws-deploy is the only runtime surface here and it holds creds -> no entry.
    reaches = cross_boundary_reaches(m)
    assert reaches == []


def test_malformed_matcher_fails_closed():
    # model_cross_boundary_reach must be exactly True.
    engine = RuleEngine()
    rule = {"id": "ATL-222", "title": "t", "severity": "high", "target": "model",
            "match": {"model_cross_boundary_reach": "yes"}, "description": "d",
            "recommendation": "r"}
    assert engine._evaluate_model_rule(rule, rule["match"], build_model(FIXTURE)) == []


# --- attestral reach: the full per-surface named-reach view ------------------

from click.testing import CliRunner  # noqa: E402

from attestral.cli import main  # noqa: E402
from attestral.cloudreach import surface_reaches  # noqa: E402


def test_surface_reaches_names_resources_and_ranks_injectable_first():
    rows = surface_reaches(build_model(FIXTURE))
    assert [r.surface for r in rows] == ["web-fetch", "aws-deploy"]  # injectable first
    web = rows[0]
    assert web.injectable and not web.holds_credential
    assert {s.resource for s in web.sinks} == {
        "aws_s3_bucket.customer_data", "aws_iam_role.deployer", "aws_dynamodb_table.sessions"}
    assert all(s.via.startswith("via ") for s in web.sinks)   # laundered, not direct
    dep = rows[1]
    assert dep.holds_credential and all(s.via == "direct" for s in dep.sinks)


def test_reach_cli_prints_named_paths_and_writes_json(tmp_path):
    r = CliRunner().invoke(main, ["reach", FIXTURE])
    assert r.exit_code == 0, r.output
    assert "Cross-boundary reach" in r.output
    assert "aws_s3_bucket.customer_data" in r.output
    assert "via aws-deploy" in r.output
    out = tmp_path / "reach.json"
    r2 = CliRunner().invoke(main, ["reach", FIXTURE, "-o", str(out)])
    assert r2.exit_code == 0 and out.exists()
    import json
    data = json.loads(out.read_text())
    surfaces = {s["surface"] for s in data["surfaces"]}
    assert "web-fetch" in surfaces


def test_reach_cli_is_empty_safe_without_cloud():
    r = CliRunner().invoke(main, ["reach", "examples/demo-project"])
    assert r.exit_code == 0
    assert "no agent surface reaches a modeled cloud" in r.output
