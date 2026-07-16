# k8s-rbac fixtures

Manifests that exercise the RBAC and NetworkPolicy component types the
kubernetes ingester emits. No rules are asserted against these yet; the
fixtures exist so a future CIS 5.1.x / 5.3.x rule wave has signal to match.
`tests/test_kubernetes_ingest.py` asserts the derived attributes below.

`rbac-and-netpol.yaml` is a single multi-document manifest (proving the
ingester picks up every `---`-separated doc) containing:

| Doc | Component type | Key attributes |
|-----|----------------|----------------|
| `Role/secret-reader` | `k8s_rbac_role` | `_grants_secrets: true`, `_is_cluster_role: false`, `namespace: app` |
| `ClusterRole/wildcard-admin` | `k8s_rbac_role` | `_wildcard_verbs: true`, `_wildcard_resources: true`, `_is_cluster_role: true` |
| `RoleBinding/bind-secret-reader` | `k8s_rbac_binding` | `_binds_cluster_admin: false`, `_is_cluster_scope: false` |
| `ClusterRoleBinding/bind-admin` | `k8s_rbac_binding` | `_binds_cluster_admin: true`, `_is_cluster_scope: true` |
| `NetworkPolicy/default-deny-ingress` | `k8s_network_policy` | `_is_default_deny: true`, `_namespace: app` |
| `NetworkPolicy/allow-frontend` | `k8s_network_policy` | `_is_default_deny: false`, `_namespace: app` |
