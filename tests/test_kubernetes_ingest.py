"""Ingester-level coverage for the Kubernetes hardening + RBAC/NetworkPolicy wave.

These assert only on the attributes and component types the kubernetes ingester
emits (no rule IDs — the rules that consume these are a separate task). Fixtures
live under examples/k8s-hardening/ and examples/k8s-rbac/. Mirrors the
build-model-from-fixture-then-assert style of tests/test_k8s_pack.py.
"""
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.model import SystemModel

HARDENING = "examples/k8s-hardening"
RBAC = "examples/k8s-rbac"


def _model(path: str) -> SystemModel:
    return ingest_kubernetes(path, SystemModel())


def _container(model: SystemModel, name: str):
    return next(c for c in model.by_type("k8s_container") if c.name == name)


def _named(model: SystemModel, type_prefix: str, name: str):
    return next(c for c in model.by_type(type_prefix) if c.name == name)


# --------------------------------------------------------------------------- #
# Pod / workload-level signals
# --------------------------------------------------------------------------- #
def test_leaky_pod_workload_signals():
    wl = _model(f"{HARDENING}/leaky-pod.yaml").by_type("k8s_workload")[0]
    assert wl.attr("host_network") is True
    assert wl.attr("host_pid") is True
    assert wl.attr("host_ipc") is True
    # serviceAccountName unset -> resolves to the risky "default".
    assert wl.attr("service_account_name") == "default"


def test_service_account_name_explicit():
    wl = _model(f"{HARDENING}/hardened-pod.yaml").by_type("k8s_workload")[0]
    assert wl.attr("service_account_name") == "app-sa"


# --------------------------------------------------------------------------- #
# Container-level hardening signals (pod-inherited resolution path)
# --------------------------------------------------------------------------- #
def test_leaky_container_signals():
    c = _container(_model(f"{HARDENING}/leaky-pod.yaml"), "app")
    # runAsUser inherited from the pod securityContext (0 == root).
    assert c.attr("run_as_user") == 0
    # AppArmor from the legacy per-container annotation, lowercased.
    assert c.attr("_apparmor_profile") == "unconfined"
    # seLinuxOptions declared at the pod level.
    assert c.attr("_has_selinux_options") is True
    # Literal value on a secret-named env var.
    assert c.attr("_env_plaintext_secret") is True
    # And the good secretKeyRef pattern is also present.
    assert c.attr("_env_uses_secret_ref") is True


# --------------------------------------------------------------------------- #
# Container-level hardening signals (container-first resolution path)
# --------------------------------------------------------------------------- #
def test_hardened_container_signals():
    c = _container(_model(f"{HARDENING}/hardened-pod.yaml"), "app")
    assert c.attr("run_as_user") == 1000
    # GA securityContext.appArmorProfile.type, lowercased.
    assert c.attr("_apparmor_profile") == "runtimedefault"
    # seLinuxOptions declared at the container level.
    assert c.attr("_has_selinux_options") is True
    # DB_PASSWORD is secret-named but sourced from a Secret, not a literal value.
    assert c.attr("_env_plaintext_secret") is False
    assert c.attr("_env_uses_secret_ref") is True


# --------------------------------------------------------------------------- #
# Unset baseline: resolvable-but-absent signals stay absent (attr_missing)
# --------------------------------------------------------------------------- #
def test_plain_container_leaves_signals_unset():
    c = _container(_model(f"{HARDENING}/plain-pod.yaml"), "app")
    assert "run_as_user" not in c.attributes
    assert "_apparmor_profile" not in c.attributes
    assert c.attr("_has_selinux_options") is False
    assert c.attr("_env_plaintext_secret") is False
    assert c.attr("_env_uses_secret_ref") is False


# --------------------------------------------------------------------------- #
# RBAC: Role / ClusterRole -> k8s_rbac_role
# --------------------------------------------------------------------------- #
def test_rbac_role_secret_reader():
    role = _named(_model(f"{RBAC}/rbac-and-netpol.yaml"), "k8s_rbac_role", "secret-reader")
    assert role.type == "k8s_rbac_role"
    assert role.attr("_grants_secrets") is True
    assert role.attr("_wildcard_verbs") is False
    assert role.attr("_wildcard_resources") is False
    assert role.attr("_is_cluster_role") is False
    assert role.attr("namespace") == "app"


def test_rbac_clusterrole_wildcards():
    role = _named(_model(f"{RBAC}/rbac-and-netpol.yaml"), "k8s_rbac_role", "wildcard-admin")
    assert role.attr("_wildcard_verbs") is True
    assert role.attr("_wildcard_resources") is True
    assert role.attr("_grants_secrets") is False
    assert role.attr("_is_cluster_role") is True
    # A ClusterRole is cluster-scoped; it carries no namespace.
    assert "namespace" not in role.attributes


# --------------------------------------------------------------------------- #
# RBAC: RoleBinding / ClusterRoleBinding -> k8s_rbac_binding
# --------------------------------------------------------------------------- #
def test_rbac_binding_namespaced():
    b = _named(_model(f"{RBAC}/rbac-and-netpol.yaml"), "k8s_rbac_binding", "bind-secret-reader")
    assert b.type == "k8s_rbac_binding"
    assert b.attr("_binds_cluster_admin") is False
    assert b.attr("_is_cluster_scope") is False


def test_rbac_clusterbinding_cluster_admin():
    b = _named(_model(f"{RBAC}/rbac-and-netpol.yaml"), "k8s_rbac_binding", "bind-admin")
    assert b.attr("_binds_cluster_admin") is True
    assert b.attr("_is_cluster_scope") is True


# --------------------------------------------------------------------------- #
# NetworkPolicy -> k8s_network_policy
# --------------------------------------------------------------------------- #
def test_network_policy_default_deny():
    np = _named(_model(f"{RBAC}/rbac-and-netpol.yaml"), "k8s_network_policy", "default-deny-ingress")
    assert np.type == "k8s_network_policy"
    assert np.attr("_is_default_deny") is True
    assert np.attr("_namespace") == "app"


def test_network_policy_targeted_allow_is_not_default_deny():
    np = _named(_model(f"{RBAC}/rbac-and-netpol.yaml"), "k8s_network_policy", "allow-frontend")
    assert np.attr("_is_default_deny") is False
    assert np.attr("_namespace") == "app"


# --------------------------------------------------------------------------- #
# Multi-document handling: one file, six new-kind components, no pod kinds
# --------------------------------------------------------------------------- #
def test_multidoc_picks_up_every_kind():
    model = _model(f"{RBAC}/rbac-and-netpol.yaml")
    assert len(model.by_type("k8s_rbac_role")) == 2
    assert len(model.by_type("k8s_rbac_binding")) == 2
    assert len(model.by_type("k8s_network_policy")) == 2
    # This fixture declares no pod-bearing kinds.
    assert model.by_type("k8s_workload") == []
