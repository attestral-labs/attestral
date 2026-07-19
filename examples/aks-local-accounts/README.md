# AKS local-accounts fixture

An Azure Kubernetes Service cluster that keeps its static, certificate-based
admin kubeconfig (`local_account_disabled = false`). That credential bypasses
Entra ID entirely: it cannot be conditional-access gated, MFA-challenged, or
centrally revoked, so a single leaked kubeconfig is non-attributable,
non-expiring cluster-admin.

```bash
attestral scan examples/aks-local-accounts
```

```
2 components · 1 finding · 1 high
```

## What fires, and why

| Cluster | Setting | Rule | Risk |
|---|---|---|---|
| `prod` | `local_account_disabled = false` | ATL-338 | Static admin kubeconfig bypasses Entra ID; unrevocable, non-attributable cluster-admin. |
| `hardened` | `local_account_disabled = true` | *(none)* | Access is per-identity through Entra ID. |

The rule fires only on the explicit `false`, never on an absent attribute, so a
cluster that never mentions the setting is silent.

## Research these checks are grounded in

- **CIS Azure Kubernetes Service Benchmark**: disable local accounts and
  authenticate through Entra ID.
- **NIST 800-53**: AC-2 (account management), IA-2 (identification &
  authentication). **SOC 2**: CC6.1.
