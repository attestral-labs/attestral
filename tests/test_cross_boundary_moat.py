"""Cross-boundary moat wave: agent-to-cloud reachability rules.

ATL-218 joins a Kubernetes ServiceAccount's IRSA role-arn (cluster boundary)
to an AWS IAM AdministratorAccess/wildcard grant (cloud boundary) by ARN-name
identity resolution - the agent-to-cloud crossing no per-component check sees.
"""
from attestral.ingest import build_model
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.ingest.terraform import ingest_terraform
from attestral.model import SystemModel
from attestral.rules import RuleEngine

POSITIVE = "examples/agent-admin-iam"
BENIGN = "examples/agent-admin-iam-benign"


def _findings(fixture):
    return RuleEngine().evaluate(build_model(fixture))


def _ids(fixture):
    return {f.rule_id for f in _findings(fixture)}


def test_atl218_fires_on_agent_admin_join():
    assert "ATL-218" in _ids(POSITIVE)


def test_atl218_fires_exactly_once():
    hits = [f for f in _findings(POSITIVE) if f.rule_id == "ATL-218"]
    assert len(hits) == 1


def test_atl218_detail_names_workload_sa_and_admin_role():
    (hit,) = [f for f in _findings(POSITIVE) if f.rule_id == "ATL-218"]
    detail = hit.description
    assert "agent-runtime" in detail
    assert "agent-sa" in detail
    assert "agent_task_role" in detail


def test_atl218_is_critical_and_attributed_to_the_workload():
    (hit,) = [f for f in _findings(POSITIVE) if f.rule_id == "ATL-218"]
    assert hit.severity.value == "critical"
    assert hit.component_id == "k8s_workload.agent-runtime"


def test_atl218_ignores_unreferenced_admin_role():
    """The break-glass admin role that no ServiceAccount references is
    over-privileged in isolation, but ATL-218 fires only on the agent->cloud
    join, so its name must never appear in any ATL-218 finding."""
    for f in _findings(POSITIVE):
        if f.rule_id == "ATL-218":
            assert "breakglass_admin" not in f.description


def test_atl218_silent_when_agent_role_is_scoped():
    """Benign fixture: the same IRSA wiring, but the assumed role holds only a
    scoped, non-wildcard policy, so the agent-to-cloud reachability exists
    without the admin blast radius. ATL-218 must not fire."""
    assert "ATL-218" not in _ids(BENIGN)


# --- ingester-edge coverage: the join keys this wave introduces --------------

def test_terraform_stamps_admin_wildcard_via_managed_arn():
    model = ingest_terraform(f"{POSITIVE}/main.tf", SystemModel())
    roles = {c.name: c for c in model.components if c.type == "aws_iam_role"}
    assert roles["agent_task_role"].attr("_admin_wildcard") is True
    assert roles["agent_task_role"].attr("_role_name") == "agent_task_role"


def test_terraform_admin_wildcard_via_inline_policy_document():
    """The scoped inline policy in the benign fixture must NOT be read as
    admin - only Action '*' on Resource '*' counts, and this is neither."""
    model = ingest_terraform(f"{BENIGN}/main.tf", SystemModel())
    roles = {c.name: c for c in model.components if c.type == "aws_iam_role"}
    assert roles["agent_task_role"].attr("_admin_wildcard") is False


def test_kubernetes_resolves_irsa_onto_workload():
    model = ingest_kubernetes(f"{POSITIVE}/deploy.yaml", SystemModel())
    (wl,) = model.by_type("k8s_workload")
    assert wl.attr("_irsa_role_arn") == (
        "arn:aws:iam::123456789012:role/agent_task_role"
    )
    sas = model.by_type("k8s_service_account")
    assert len(sas) == 1 and sas[0].name == "agent-sa"


def test_agent_reaches_admin_matcher_fails_closed_on_non_true():
    """A non-True spec value must yield no findings (typed, fail-closed)."""
    from attestral.rules.engine import RuleEngine as RE
    eng = RE()
    model = build_model(POSITIVE)
    for bad in ("true", 1, {}, ["x"], None):
        rule = {"id": "X", "title": "t", "severity": "critical",
                "match": {"model_agent_reaches_admin_iam": bad}}
        assert eng._evaluate_model_rule(rule, rule["match"], model) == []
