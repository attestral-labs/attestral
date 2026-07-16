# k8s-hardening fixtures

Pods that exercise the pod- and container-level Pod-Security-Standards /
CIS 5.2.x / 5.4.x signals the kubernetes ingester now emits. No rules are
asserted against these yet; `tests/test_kubernetes_ingest.py` asserts the
derived attributes so a future rule wave has verified signal.

| File | Component | Risky signals it sets |
|------|-----------|-----------------------|
| `leaky-pod.yaml` | `k8s_workload` | `host_network/host_pid/host_ipc: true`, `service_account_name: default` |
| `leaky-pod.yaml` | `k8s_container` | `run_as_user: 0`, `_apparmor_profile: unconfined`, `_has_selinux_options: true`, `_env_plaintext_secret: true`, `_env_uses_secret_ref: true` |
| `hardened-pod.yaml` | `k8s_workload` | `service_account_name: app-sa` (non-default) |
| `hardened-pod.yaml` | `k8s_container` | `run_as_user: 1000`, `_apparmor_profile: runtimedefault`, `_has_selinux_options: true` (container level), `_env_plaintext_secret: false`, `_env_uses_secret_ref: true` |
| `plain-pod.yaml` | `k8s_container` | `run_as_user`/`_apparmor_profile` absent, `_has_selinux_options: false`, both env signals false |

`leaky-pod.yaml` sets the fields at the POD securityContext / annotation level;
`hardened-pod.yaml` sets them at the CONTAINER level, so between them both
resolution paths (container-first, pod-fallback) are covered.
