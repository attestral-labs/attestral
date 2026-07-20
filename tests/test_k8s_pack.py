"""Coverage for the Kubernetes hardening pack (rules/k8s_pack.yaml).

CIS Kubernetes Benchmark 5.x + Pod Security Standards checks layered on top of
the core K8s rules ATL-501..510. Also unit-tests the new derived attributes the
kubernetes ingester was extended to emit so these rules have signal to match.
"""
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

FIXTURE = "examples/k8s-pack"

# ATL-511 .. ATL-525 inclusive.
NEW_IDS = {f"ATL-{n}" for n in range(511, 526)}




def test_all_k8s_pack_rules_fire():
    fired = ids_for(FIXTURE)
    missing = NEW_IDS - fired
    assert not missing, f"pack rules never fired: {sorted(missing)}"


def test_no_duplicate_rule_ids():
    ids = [r["id"] for r in RuleEngine().rules]
    assert len(ids) == len(set(ids))


def test_k8s_pack_ids_present():
    ids = {r["id"] for r in RuleEngine().rules}
    assert NEW_IDS <= ids


def test_ingester_emits_new_derived_attrs():
    model = ingest_kubernetes(f"{FIXTURE}/insecure-deploy.yaml", SystemModel())
    wl = model.by_type("k8s_workload")[0]
    assert wl.attr("namespace") == "default"
    assert wl.attr("host_ipc") is True
    app = next(c for c in model.by_type("k8s_container") if c.name == "app")
    assert app.attr("_image_untagged") is True
    assert app.attr("_drops_all_caps") is False
    assert app.attr("_has_requests") is False
    assert app.attr("_has_probes") is False
    assert app.attr("_has_host_port") is True
    assert app.attr("image_pull_policy") == "IfNotPresent"
    # Container has no seccomp of its own; it inherits the pod-level Unconfined.
    assert app.attr("seccomp_profile") == "Unconfined"


def test_seccomp_missing_and_hardened_signals():
    model = ingest_kubernetes(f"{FIXTURE}/root-worker.yaml", SystemModel())
    worker = model.by_type("k8s_container")[0]
    # Neither container nor pod sets seccomp, so the attr is absent (ATL-520).
    assert worker.attr("seccomp_profile") is None
    assert worker.attr("run_as_non_root") is False
    assert worker.attr("_drops_all_caps") is True
    assert worker.attr("namespace") is None  # namespace lives on the workload
    wl = model.by_type("k8s_workload")[0]
    assert wl.attr("namespace") == "apps"
