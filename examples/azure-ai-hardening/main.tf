# Azure AI Foundry / AI Services agent-hosting hardening fixture. Each `_weak`
# resource trips a rule; the `_hardened` counterpart is the correct form and stays
# silent, so the fixture pins precision, not just recall.

# --- ATL-339: AI Services account (agent host) without a customer-managed key ---
# Gated on kind = "AIServices" so it is an agent-hosting finding, not a generic
# Cognitive-services check.
resource "azurerm_cognitive_account" "agents_weak" {
  name                = "shipping-ai"
  location            = "eastus"
  resource_group_name = "agents"
  kind                = "AIServices"
  sku_name            = "S0"
}

resource "azurerm_cognitive_account" "agents_hardened" {
  name                = "billing-ai"
  location            = "eastus"
  resource_group_name = "agents"
  kind                = "AIServices"
  sku_name            = "S0"
  customer_managed_key {
    key_vault_key_id = "https://agents-kv.vault.azure.net/keys/ai/1"
  }
}

# --- ATL-340 + ATL-341: AI Foundry hub public + without CMK -----------------
resource "azurerm_ai_foundry" "hub_weak" {
  name                  = "shipping-hub"
  location              = "eastus"
  resource_group_name   = "agents"
  storage_account_id    = "/subscriptions/x/resourceGroups/agents/providers/Microsoft.Storage/storageAccounts/hub"
  key_vault_id          = "/subscriptions/x/resourceGroups/agents/providers/Microsoft.KeyVault/vaults/hub"
  public_network_access = "Enabled"
  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_ai_foundry" "hub_hardened" {
  name                  = "billing-hub"
  location              = "eastus"
  resource_group_name   = "agents"
  storage_account_id    = "/subscriptions/x/resourceGroups/agents/providers/Microsoft.Storage/storageAccounts/hub2"
  key_vault_id          = "/subscriptions/x/resourceGroups/agents/providers/Microsoft.KeyVault/vaults/hub2"
  public_network_access = "Disabled"
  identity {
    type = "SystemAssigned"
  }
  encryption {
    key_id       = "https://agents-kv.vault.azure.net/keys/hub/1"
    key_vault_id = "/subscriptions/x/resourceGroups/agents/providers/Microsoft.KeyVault/vaults/hub2"
  }
}
