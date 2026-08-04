# k8s-privesc fixtures

The two Kubernetes privilege-escalation signals earlier waves flagged as
ingester gaps, now ingested and ruled: the concrete node path behind a
`hostPath` volume (`_hostpath_paths`) and the full verb list on a
Role/ClusterRole (`_verbs`). A pod that mounts the container runtime socket
holds root on its node behind one API call; a role that grants
`escalate`/`bind`/`impersonate` lets its subjects become more privileged than
they were ever granted.

```bash
attestral scan examples/k8s-privesc
```

```
7 components · 5 findings · 1 critical · 4 high
```

## What fires, and why

| File | Component | Rule | Risk |
|---|---|---|---|
| `runtime-socket.yaml` | `ci-runner` | ATL-536 (critical) | Mounts `/var/run/docker.sock`; whoever reaches the socket can start privileged containers and own the node. |
| `runtime-socket.yaml` | `ci-runner` | ATL-510 (high) | The same mount is also a generic `hostPath` volume - both findings are real. |
| `escalation-role.yaml` | `release-operator` | ATL-537 (high) | ClusterRole grants `bind` + `escalate` over clusterroles. |
| `escalation-role.yaml` | `support-impersonator` | ATL-537 (high) | Role grants `impersonate` over users/groups. |
| `control.yaml` | `log-agent` | ATL-510 (high) | Benign `/var/log` read-only hostPath: the generic rule fires, the socket rule stays silent. |
| `control.yaml` | `log-reader` | *(none)* | `get`/`list`/`watch` only - no escalation verb, no wildcard, no secrets. |

Both containers are hardened on every other axis (non-root, no privilege
escalation, seccomp RuntimeDefault, ALL capabilities dropped, read-only root,
digest-pinned images, limits/requests/probes), so the wave's rules are the only
signal. Precision notes: ATL-536 matches the socket path exactly (a `/var/run`
parent-dir mount is ATL-510's job, never guessed into a socket finding), and
ATL-537 deliberately ignores wildcard `*` verbs - that is ATL-533's finding,
not a double report.

## Research these checks are grounded in

- **NSA/CISA Kubernetes Hardening Guidance v1.2**: protect the container
  runtime socket; a pod that can reach it controls every container on the node.
- **CIS Kubernetes Benchmark 5.1.8**: limit use of the `bind`, `impersonate`
  and `escalate` permissions - the three verbs that transcend a subject's own
  grant.
- **CIS Kubernetes Benchmark 5.2.x**: minimize hostPath admission (ATL-510,
  the co-firing generic rule).
