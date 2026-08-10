# Azure AI Foundry / AI Services hardening fixture

The Azure half of the AI-cloud agent-runtime moat: the AI Services account
(`azurerm_cognitive_account` with `kind = "AIServices"`) that hosts Foundry
agents, and the AI Foundry hub. Each `_weak` resource trips a rule; the
`_hardened` counterpart is the correct form and stays silent.

```bash
attestral scan examples/azure-ai-hardening
```

```
4 components · 3 findings · 1 high · 2 medium
```

- `azurerm_cognitive_account.agents_weak` - `kind = "AIServices"` with no
  `customer_managed_key`, so the agent account's data is under a
  Microsoft-managed key. Fires **ATL-339** (the rule is gated on the AIServices
  kind, so it stays an agent-hosting finding, not a generic Cognitive check).
- `azurerm_ai_foundry.hub_weak` - `public_network_access = "Enabled"`, so the
  credential-holding agent workspace is reachable from the internet (fires
  **ATL-340**, high), and it declares no `encryption` block, so the hub is under
  a Microsoft-managed key (fires **ATL-341**).

The `_hardened` account sets a customer-managed key; the `_hardened` hub uses
`public_network_access = "Disabled"` and an `encryption` block.
