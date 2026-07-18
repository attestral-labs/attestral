# AKS static local-account kubeconfig (ATL-338).
# `prod` keeps local accounts enabled (bypasses Entra ID); `hardened` disables them.

resource "azurerm_kubernetes_cluster" "prod" {
  name                   = "prod-aks"
  location               = "eastus"
  resource_group_name    = "rg-prod"
  dns_prefix             = "prodaks"
  local_account_disabled = false

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}

resource "azurerm_kubernetes_cluster" "hardened" {
  name                   = "hardened-aks"
  location               = "eastus"
  resource_group_name    = "rg-prod"
  dns_prefix             = "hardaks"
  local_account_disabled = true

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_D2_v2"
  }

  identity {
    type = "SystemAssigned"
  }
}
