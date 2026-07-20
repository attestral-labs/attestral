"""Coverage for the v0.6 rule-pack expansion: AWS extras, Azure, GCP, K8s."""
from attestral.ingest import build_model
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

FIXTURE = "examples/multicloud-k8s"




def test_new_aws_rules_fire():
    assert {
        "ATL-019", "ATL-020", "ATL-021", "ATL-022",
        "ATL-023", "ATL-024", "ATL-025", "ATL-026",
    } <= ids_for(FIXTURE)


def test_azure_rules_fire():
    assert {
        "ATL-301", "ATL-302", "ATL-303", "ATL-304", "ATL-305", "ATL-306",
        "ATL-307", "ATL-308", "ATL-309", "ATL-310", "ATL-311", "ATL-312",
        "ATL-313", "ATL-314", "ATL-315", "ATL-316",
    } <= ids_for(FIXTURE)


def test_gcp_rules_fire():
    assert {
        "ATL-401", "ATL-402", "ATL-403", "ATL-404", "ATL-405",
        "ATL-406", "ATL-407", "ATL-408", "ATL-409", "ATL-410",
        "ATL-411", "ATL-412", "ATL-413",
    } <= ids_for(FIXTURE)


def test_kubernetes_rules_fire():
    ids = ids_for(FIXTURE)
    assert {
        "ATL-501", "ATL-502", "ATL-503", "ATL-504", "ATL-505",
        "ATL-506", "ATL-507", "ATL-508", "ATL-509", "ATL-510",
    } <= ids


def test_kubernetes_hardening_rules_fire():
    """The ingester-expansion wave: AppArmor-unconfined and plaintext env
    secrets, over the k8s-hardening fixture (leaky-pod triggers both)."""
    model = build_model("examples/k8s-hardening")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert {"ATL-530", "ATL-531"} <= ids


def test_kubernetes_rbac_rules_fire():
    """RBAC/binding component types from the ingester expansion: wildcard
    verbs/resources, secrets access, and a cluster-admin binding."""
    model = build_model("examples/k8s-rbac")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert {"ATL-532", "ATL-533", "ATL-534", "ATL-535"} <= ids


def test_rule_pack_has_no_duplicate_ids():
    rules = RuleEngine().rules
    ids = [r["id"] for r in rules]
    assert len(ids) == len(set(ids))
    assert len(ids) >= 55


def test_k8s_ingester_flattens_container_and_workload():
    model = ingest_kubernetes(f"{FIXTURE}/workload.yaml", SystemModel())
    workloads = model.by_type("k8s_workload")
    containers = model.by_type("k8s_container")
    assert len(workloads) == 1 and len(containers) == 1
    wl, c = workloads[0], containers[0]
    assert wl.attr("host_network") is True
    assert wl.attr("host_pid") is True
    assert "hostPath" in wl.attr("_volume_types")
    assert c.attr("privileged") is True
    assert c.attr("run_as_user") == 0
    assert c.attr("_has_limits") is False
    assert "SYS_ADMIN" in c.attr("_capabilities_add")
    assert c.attr("image") == "acme/api:latest"


def test_k8s_ingester_ignores_non_manifest_yaml(tmp_path):
    (tmp_path / "config.yaml").write_text("database:\n  host: localhost\n")
    model = ingest_kubernetes(tmp_path, SystemModel())
    assert model.components == []


def test_image_untagged_flag(tmp_path):
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"
        "spec:\n  containers:\n    - name: c\n      image: registry:5000/app\n"
    )
    model = ingest_kubernetes(tmp_path, SystemModel())
    c = model.by_type("k8s_container")[0]
    # A registry:port host must not be read as an image tag.
    assert c.attr("_image_untagged") is True
