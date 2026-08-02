# Agent-cloud mesh fixture: component-to-component edges

One small design spanning all three trust boundaries, built to exercise the
component-to-component edge families the ingesters emit. Before these edges,
consumers that reason over the graph (blast-radius adjacency, the topography
mesh, the proof walker) saw sentinel targets only; this fixture makes every
family visible between real components:

- **`references` (Terraform)** - `aws_instance.runner` names its security
  group and instance profile, the profile and the policy attachment name
  `aws_iam_role.deployer`. Four declared reference edges, resolved by resource
  address within the same module scope.
- **`routes_to` / `uses_service_account` (Kubernetes)** - `web-svc` selects
  the `web` Deployment's pod labels (`app: web`), and `web` runs as the
  modeled `deploy-bot` ServiceAccount (which carries an IRSA role annotation,
  the identity hop toward the cloud grant).
- **`credential_reach` (agent-to-cloud)** - `aws-deploy` holds AWS keys in its
  env, so it gets one inferred edge to each `aws_*` component in the scan,
  same provider only. The `boundary:cloud` sentinel edge is still emitted
  alongside; the sentinel attests THAT the crossing exists, the per-component
  edges say WHICH resources it reaches.

```bash
attestral scan examples/agent-cloud-mesh
```

11 components · 3 findings · 1 high · 1 medium · 1 info

| Rule | Severity | Why |
|---|---|---|
| ATL-112 | high | `aws-deploy` holds raw cloud credentials - the crossing the `credential_reach` edges make graph-visible. |
| ATL-104 | medium | The AWS secret is passed to the server via env. |
| ATL-201 | info | Agent runtime and cloud share no declared boundary controls. |

The Kubernetes side is deliberately hardened (non-root, dropped capabilities,
seccomp, read-only rootfs, no automounted SA token), so the finding list stays
about the agent-to-cloud story while the edge families still have full signal.
`tests/test_component_edges.py` asserts every edge this fixture emits.
