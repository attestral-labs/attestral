# EC2 launch-template IMDSv2 fixture

A launch template - the path Auto Scaling Groups and EKS managed node groups
actually use - that leaves the instance metadata service answering IMDSv1.
ATL-033 only covers standalone `aws_instance`; this closes the same gap on the
template that backs a fleet.

```bash
attestral scan examples/aws-launch-template
```

```
2 components · 1 finding · 1 high
```

## What fires, and why

| Template | metadata_options | Rule | Risk |
|---|---|---|---|
| `workers` | `http_tokens = "optional"`, hop limit 2 | ATL-069 | Every node it backs answers IMDSv1, so a pod-level SSRF can steal the node role's credentials with no session token. |
| `workers_hardened` | `http_tokens = "required"`, hop limit 1 | *(none)* | IMDSv2 enforced, single hop. |

The rule fires only on the explicit `optional` token, never on an absent
`metadata_options` block.

## Research these checks are grounded in

- **CIS AWS Foundations Benchmark 5.6**: "Ensure that EC2 Metadata Service only
  allows IMDSv2." **CIS Amazon EKS Benchmark**: restrict node metadata access.
- **NIST 800-53**: AC-6 (least privilege), SC-7 (boundary protection).
- Instance-role credential theft via IMDSv1 SSRF is the pod -> node-role
  toxic-flow this pack models across the agent -> cloud boundary.
