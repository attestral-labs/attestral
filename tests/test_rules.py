from attestral.ingest import build_model
from attestral.rules import RuleEngine


def _findings():
    model = build_model("examples/demo-project")
    return model, RuleEngine().evaluate(model)


def test_model_builds_components():
    model, _ = _findings()
    assert len(model.components) == 8  # 4 tf + 4 mcp


def test_cloud_rules_fire():
    _, findings = _findings()
    ids = {f.rule_id for f in findings}
    assert {"ATL-001", "ATL-002", "ATL-003", "ATL-004"} <= ids


def test_mcp_rules_fire():
    _, findings = _findings()
    ids = {f.rule_id for f in findings}
    assert {"ATL-101", "ATL-102", "ATL-103", "ATL-104"} <= ids


def test_cross_boundary_model_rule_fires():
    _, findings = _findings()
    assert "ATL-201" in {f.rule_id for f in findings}


def test_auto_install_rule_fires_on_dash_y():
    # ATL-105: `npx -y` style auto-install at launch. vulnerable-agent plants
    # it on two servers; assert the components so the check is direct, not
    # just implied by the fixture-README count sync.
    model = build_model("examples/vulnerable-agent")
    findings = RuleEngine().evaluate(model)
    hits = {f.component_id for f in findings if f.rule_id == "ATL-105"}
    assert hits == {"mcp_server.filesystem", "mcp_server.web"}


def test_findings_sorted_by_severity():
    _, findings = _findings()
    ranks = [f.severity.rank for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_attr_missing_fires_only_on_exact_target_type():
    """`attr_missing` must fire only on the EXACT target type, never on a
    prefix-sharing sibling. A google_vertex_ai_reasoning_engine_iam_member
    trivially lacks kms_key_name, but it is not a reasoning engine, so ATL-435
    (attr_missing kms_key_name) must not flag it - the vacuous-false-positive
    caught by scanning real provider Terraform. Non-attr_missing matchers keep
    the intended prefix reach (aws_s3_bucket -> aws_s3_bucket_acl)."""
    from attestral.model import Component, SystemModel
    m = SystemModel()
    m.add(Component(id="google_vertex_ai_reasoning_engine.x",
                    type="google_vertex_ai_reasoning_engine", name="x",
                    source="s", attributes={}, trust_boundary="cloud"))
    m.add(Component(id="google_vertex_ai_reasoning_engine_iam_member.x",
                    type="google_vertex_ai_reasoning_engine_iam_member", name="x",
                    source="s", attributes={}, trust_boundary="cloud"))
    hits = [f for f in RuleEngine().evaluate(m) if f.rule_id == "ATL-435"]
    assert len(hits) == 1
    assert hits[0].component_id == "google_vertex_ai_reasoning_engine.x"


def test_split_resource_prefix_reach_preserved():
    """The intended prefix behaviour survives: ATL-002 (open security group)
    still fires on a standalone aws_security_group_rule, not just an inline
    aws_security_group."""
    from attestral.model import Component, SystemModel
    m = SystemModel()
    m.add(Component(id="aws_security_group_rule.ssh", type="aws_security_group_rule",
                    name="ssh", source="s",
                    attributes={"_ingress_cidr_blocks": ["0.0.0.0/0"]},
                    trust_boundary="cloud"))
    assert "ATL-002" in {f.rule_id for f in RuleEngine().evaluate(m)}
