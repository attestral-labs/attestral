"""Component-to-component edges emitted by the ingest wave.

Three families, all statically derivable from config and all fail-closed:
`references` (Terraform attribute references resolved by resource address),
`routes_to` / `uses_service_account` (Kubernetes selector and identity links),
and `credential_reach` (a cloud-credential-holding surface reaches each
same-provider cloud component). The sentinel edges (`taint:*`,
`boundary:cloud`) predate this wave and must survive it unchanged - the proof
walker and whatif rederivation key on them.
"""
from attestral.ingest import build_model
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.ingest.mcp import ingest_mcp
from attestral.ingest.terraform import ingest_terraform
from attestral.model import SystemModel

FIXTURE = "examples/agent-cloud-mesh"


def _edges(model, kind):
    return [(e.source_id, e.target_id) for e in model.edges if e.kind == kind]


# --- terraform `references` ---------------------------------------------------

def test_terraform_reference_edges_on_fixture():
    model = build_model(FIXTURE)
    assert set(_edges(model, "references")) == {
        ("aws_instance.runner", "aws_security_group.agent_runner"),
        ("aws_instance.runner", "aws_iam_instance_profile.runner"),
        ("aws_iam_instance_profile.runner", "aws_iam_role.deployer"),
        ("aws_iam_role_policy_attachment.deployer_readonly", "aws_iam_role.deployer"),
    }


def test_terraform_reference_edge_records_declaring_attr():
    model = build_model(FIXTURE)
    edge = next(
        e for e in model.edges
        if e.kind == "references"
        and e.source_id == "aws_instance.runner"
        and e.target_id == "aws_security_group.agent_runner"
    )
    assert edge.attributes["via"] == ["vpc_security_group_ids"]


def test_terraform_reference_to_absent_resource_is_no_edge(tmp_path):
    # An address that names nothing in the scan must emit nothing (fail closed).
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "app" {\n'
        '  vpc_security_group_ids = [aws_security_group.elsewhere.id]\n'
        '}\n'
    )
    model = ingest_terraform(tmp_path, SystemModel())
    assert _edges(model, "references") == []


def test_terraform_lookalike_string_is_no_edge(tmp_path):
    # A dotted literal (a hostname) is not a resource address in this scan.
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "app" {\n'
        '  ami = "ami-123"\n'
        '  user_data = "curl internal.acme.dev/bootstrap"\n'
        '}\n'
        'resource "aws_s3_bucket" "logs" {\n'
        '  bucket = "logs"\n'
        '}\n'
    )
    model = ingest_terraform(tmp_path, SystemModel())
    assert _edges(model, "references") == []


def test_terraform_module_scope_bounds_the_reference(tmp_path):
    # A module-local reference binds inside the module instance, never to a
    # same-named root resource.
    (tmp_path / "main.tf").write_text(
        'module "net" { source = "./net" }\n'
        'resource "aws_security_group" "sg" { name = "root-sg" }\n'
    )
    mod = tmp_path / "net"
    mod.mkdir()
    (mod / "main.tf").write_text(
        'resource "aws_security_group" "sg" { name = "mod-sg" }\n'
        'resource "aws_instance" "app" {\n'
        '  vpc_security_group_ids = [aws_security_group.sg.id]\n'
        '}\n'
    )
    model = ingest_terraform(tmp_path, SystemModel())
    assert _edges(model, "references") == [
        ("module.net.aws_instance.app", "module.net.aws_security_group.sg"),
    ]


# --- kubernetes `routes_to` / `uses_service_account` --------------------------

def test_service_selector_match_emits_routes_to():
    model = build_model(FIXTURE)
    assert _edges(model, "routes_to") == [
        ("k8s_service.agents.web-svc", "k8s_workload.web"),
    ]


def test_service_selector_mismatch_is_no_edge(tmp_path):
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n"
        "  labels: {app: web}\nspec:\n  containers: [{name: c, image: i:1}]\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n"
        "spec:\n  selector: {app: api}\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    assert _edges(model, "routes_to") == []


def test_service_selector_never_matches_across_namespaces(tmp_path):
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n  namespace: prod\n"
        "  labels: {app: web}\nspec:\n  containers: [{name: c, image: i:1}]\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\n  namespace: dev\n"
        "spec:\n  selector: {app: web}\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    assert _edges(model, "routes_to") == []


def test_empty_selector_is_no_edge(tmp_path):
    # A Service without a selector (headless/ExternalName shape) routes to
    # nothing statically decidable.
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n"
        "  labels: {app: web}\nspec:\n  containers: [{name: c, image: i:1}]\n"
        "---\n"
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec: {}\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    assert _edges(model, "routes_to") == []


def test_workload_links_to_modeled_service_account():
    model = build_model(FIXTURE)
    assert _edges(model, "uses_service_account") == [
        ("k8s_workload.web", "k8s_service_account.agents.deploy-bot"),
    ]


def test_unmodeled_service_account_is_no_edge(tmp_path):
    # The workload names an SA, but no ServiceAccount doc is in the scan.
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n"
        "spec:\n  serviceAccountName: ghost\n"
        "  containers: [{name: c, image: i:1}]\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    assert _edges(model, "uses_service_account") == []


# --- `credential_reach` -------------------------------------------------------

def test_credential_reach_covers_every_same_provider_component():
    model = build_model(FIXTURE)
    aws_ids = {c.id for c in model.components if c.type.startswith("aws_")}
    reach = _edges(model, "credential_reach")
    assert {t for _, t in reach} == aws_ids
    assert all(s == "mcp_server.aws-deploy" for s, _ in reach)


def test_credential_reach_is_same_provider_only(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "a" { bucket = "a" }\n'
        'resource "google_storage_bucket" "g" { name = "g" }\n'
        'resource "azurerm_storage_account" "z" { name = "z" }\n'
    )
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"deploy": {"command": "uvx", "args": ["x"],'
        ' "env": {"AWS_ACCESS_KEY_ID": "k", "AWS_SECRET_ACCESS_KEY": "s"}}}}'
    )
    model = build_model(tmp_path)
    assert _edges(model, "credential_reach") == [
        ("mcp_server.deploy", "aws_s3_bucket.a"),
    ]


def test_credential_reach_from_k8s_container(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_s3_bucket" "a" { bucket = "a" }\n'
    )
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: gw\n"
        "spec:\n  containers:\n    - name: gateway\n      image: i:1\n"
        "      env:\n"
        "        - {name: AWS_ACCESS_KEY_ID, value: k}\n"
        "        - {name: AWS_SECRET_ACCESS_KEY, value: s}\n"
    )
    model = build_model(tmp_path)
    assert _edges(model, "credential_reach") == [
        ("k8s_container.gw.gateway", "aws_s3_bucket.a"),
    ]


def test_no_cloud_components_means_no_credential_reach(tmp_path):
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"deploy": {"command": "uvx", "args": ["x"],'
        ' "env": {"AWS_ACCESS_KEY_ID": "k"}}}}'
    )
    model = build_model(tmp_path)
    assert _edges(model, "credential_reach") == []
    # The sentinel crossing still holds without any modeled cloud component.
    assert ("mcp_server.deploy", "boundary:cloud") in _edges(model, "tool_access")


def test_credential_reach_cap_bounds_a_large_estate(tmp_path):
    from attestral.ingest.scan import _CREDENTIAL_REACH_CAP
    n = _CREDENTIAL_REACH_CAP + 10
    tf = "".join(
        f'resource "aws_s3_bucket" "b{i:03d}" {{ bucket = "b{i:03d}" }}\n'
        for i in range(n)
    )
    (tmp_path / "main.tf").write_text(tf)
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"deploy": {"command": "uvx", "args": ["x"],'
        ' "env": {"AWS_ACCESS_KEY_ID": "k"}}}}'
    )
    model = build_model(tmp_path)
    reach = _edges(model, "credential_reach")
    assert len(reach) == _CREDENTIAL_REACH_CAP
    # Deterministic sample: the first N targets in sorted-id order.
    assert [t for _, t in reach] == sorted(t for _, t in reach)
    # The sentinel edge still attests the full crossing beyond the cap.
    assert ("mcp_server.deploy", "boundary:cloud") in _edges(model, "tool_access")


# --- invariants over the whole graph ------------------------------------------

def test_sentinel_edges_are_preserved():
    model = build_model("examples/agentic-risks")
    kinds = {e.kind for e in model.edges}
    assert "taint_source" in kinds and "taint_sink" in kinds
    assert any(
        e.kind == "tool_access" and e.target_id == "boundary:cloud"
        for e in model.edges
    )


def test_no_self_edges_on_fixtures():
    for fixture in (FIXTURE, "examples/agentic-risks", "examples/demo-project"):
        model = build_model(fixture)
        assert all(e.source_id != e.target_id for e in model.edges), fixture


def test_edge_emission_is_deterministic():
    a = build_model(FIXTURE)
    b = build_model(FIXTURE)
    assert [(e.source_id, e.target_id, e.kind, e.attributes) for e in a.edges] == [
        (e.source_id, e.target_id, e.kind, e.attributes) for e in b.edges
    ]


def test_repeat_ingest_never_duplicates_link_edges(tmp_path):
    (tmp_path / "app.yaml").write_text(
        "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: sa}\n"
        "---\n"
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n"
        "  labels: {app: web}\n"
        "spec:\n  serviceAccountName: sa\n"
        "  containers: [{name: c, image: i:1}]\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    ingest_kubernetes(tmp_path, model)  # second pass over the same model
    # Each pass links only the components it emitted - no cross-pass duplicates.
    assert len(_edges(model, "uses_service_account")) == 2


def test_credential_reach_crosses_the_boundary_in_topography():
    # The payoff: the mesh renders agent -> cloud as a cross-boundary edge.
    from attestral.topography import build_topography
    model = build_model(FIXTURE)
    data = build_topography(model, [])
    cross = [e for e in data["edges"] if e["cross"]]
    assert any(
        e["s"] == "mcp_server.aws-deploy" and e["t"].startswith("aws_")
        for e in cross
    )


def test_mcp_only_scan_gets_no_component_reach(tmp_path):
    # ingest_mcp alone (no build_model) emits no credential_reach - the family
    # is a model-level join, derived once the whole scan is assembled.
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"deploy": {"command": "uvx", "args": ["x"],'
        ' "env": {"AWS_ACCESS_KEY_ID": "k"}}}}'
    )
    model = ingest_mcp(tmp_path / "mcp.json", SystemModel())
    assert _edges(model, "credential_reach") == []
