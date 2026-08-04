# k8s-pack-ext fixtures

Triggering manifests for the Kubernetes hardening pack extension wave
(`rules/k8s_pack.yaml`, ATL-526..529). These check attributes the kubernetes
ingester already emits and that ATL-501..525 do not already cover.

| File | Fires | Control |
|------|-------|---------|
| `dangerous-caps.yaml` | ATL-526 | adds `SYS_RAWIO` + `SYS_TIME` (second-tier caps beyond ATL-503) |
| `gitrepo-volume.yaml` | ATL-527 | deprecated `gitRepo` volume (CVE-2024-10220 node RCE) |
| `flexvolume.yaml` | ATL-528 | deprecated `flexVolume` out-of-tree driver volume |
| `kube-system-workload.yaml` | ATL-529 | application `Deployment` in `kube-system` |
| `compliant.yaml` | none of 526-529 | hardened workload in a dedicated namespace |

`compliant.yaml` is the negative fixture: it adds only `NET_BIND_SERVICE`
(not in the ATL-526 list), mounts only an `emptyDir`, and lives in the
`payments` namespace, so none of the extension rules fire on it. It may still
trigger other, pre-existing k8s rules; the tests assert only on ATL-526..529.

## Ingester coverage gap (ingester-builder follow-on)

These requested Pod Security / CIS controls could NOT be authored because the
kubernetes ingester does not yet emit the needed signal:

- AppArmor profile (CIS 5.2.11) and SELinux options (CIS 5.2.12)
- `procMount`, `sysctls`, `windowsOptions`, `seLinuxOptions`
- `emptyDir` `sizeLimit` / `medium: Memory` (only the volume type key is emitted)
- `serviceAccountName` / default-service-account use (CIS 5.1.5)
- Role / ClusterRole / RoleBinding wildcard RBAC (CIS 5.1.3)
- NetworkPolicy presence per namespace (CIS 5.3.2)
- secrets referenced via `env` value vs `secretKeyRef` (CIS 5.4.1)
- image pinned by digest vs tag (no negation matcher; needs `_image_has_digest`)
- container-runtime-socket / sensitive host mounts (only the `hostPath` type key
  is emitted, not the mounted path) - **closed**: the ingester now emits
  `_hostpath_paths` and ATL-536 rules on it (`examples/k8s-privesc/`)
