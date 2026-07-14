# Intentionally insecure Azure fixtures for the Attestral azure_pack.yaml pack
# (ATL-317..ATL-336). Every resource below is minimal and authored to trigger
# exactly the pack rule(s) noted in the comments, without tripping the core
# Azure rules (ATL-301..316) that live in core_rules.yaml.
#
# The terraform ingester flattens nested HCL blocks into a flat attribute dict
# (last-key-wins on collisions), so each matched attribute here is unique within
# its resource.

# --- Storage: shared-key auth on, public network on, blob versioning off -----
# Fires ATL-317, ATL-318, ATL-319 on one account.
resource "azurerm_storage_account" "data" {
  name                          = "acmepackdata"
  resource_group_name           = "acme-rg"
  location                      = "eastus"
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  shared_access_key_enabled     = true   # ATL-317
  public_network_access_enabled = true   # ATL-319

  blob_properties {
    versioning_enabled = false           # ATL-318
  }
}

# --- Key Vault: access-policy authorization instead of RBAC -------------------
# Fires ATL-320 (purge protection / public access left at safe defaults so the
# core KV rules ATL-305 / ATL-311 do not fire).
resource "azurerm_key_vault" "kv" {
  name                       = "acme-pack-kv"
  resource_group_name        = "acme-rg"
  location                   = "eastus"
  tenant_id                  = "00000000-0000-0000-0000-000000000000"
  sku_name                   = "standard"
  enable_rbac_authorization  = false      # ATL-320
}

# --- Cosmos DB: reachable from the public internet ---------------------------
# Fires ATL-321.
resource "azurerm_cosmosdb_account" "cosmos" {
  name                          = "acme-pack-cosmos"
  resource_group_name           = "acme-rg"
  location                      = "eastus"
  offer_type                    = "Standard"
  public_network_access_enabled = true    # ATL-321
}

# --- Redis: non-TLS port open and legacy TLS floor ---------------------------
# Fires ATL-322, ATL-323.
resource "azurerm_redis_cache" "cache" {
  name                = "acme-pack-cache"
  resource_group_name = "acme-rg"
  location            = "eastus"
  capacity            = 1
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = true              # ATL-322
  minimum_tls_version = "1.0"             # ATL-323
}

# --- Container Registry: admin account + anonymous pull ----------------------
# Fires ATL-324, ATL-325.
resource "azurerm_container_registry" "acr" {
  name                   = "acmepackacr"
  resource_group_name    = "acme-rg"
  location               = "eastus"
  sku                    = "Standard"
  admin_enabled          = true           # ATL-324
  anonymous_pull_enabled = true           # ATL-325
}

# --- App Service: legacy TLS, plaintext FTP, remote debugging ----------------
# https_only = true keeps core ATL-313 quiet; fires ATL-326, ATL-327, ATL-328.
resource "azurerm_linux_web_app" "web" {
  name                = "acme-pack-web"
  resource_group_name = "acme-rg"
  location            = "eastus"
  service_plan_id     = "acme-plan"
  https_only          = true

  site_config {
    minimum_tls_version      = "1.1"      # ATL-326
    ftps_state               = "AllAllowed" # ATL-327
    remote_debugging_enabled = true       # ATL-328
  }
}

# --- Function App: answers plaintext HTTP ------------------------------------
# Fires ATL-329 (distinct resource type from the web app in ATL-313).
resource "azurerm_linux_function_app" "func" {
  name                = "acme-pack-func"
  resource_group_name = "acme-rg"
  location            = "eastus"
  service_plan_id     = "acme-plan"
  https_only          = false             # ATL-329
}

# --- AKS: Kubernetes RBAC off, Azure Policy add-on off, public API server ----
# local_account_enabled left unset so core ATL-315 does not fire; fires
# ATL-330, ATL-331, ATL-332.
resource "azurerm_kubernetes_cluster" "aks" {
  name                              = "acme-pack-aks"
  resource_group_name               = "acme-rg"
  location                          = "eastus"
  dns_prefix                        = "acmepack"
  role_based_access_control_enabled = false   # ATL-330
  azure_policy_enabled              = false   # ATL-331
  private_cluster_enabled           = false   # ATL-332
}

# --- Service Bus: SAS local auth on, legacy TLS floor ------------------------
# Fires ATL-333, ATL-334.
resource "azurerm_servicebus_namespace" "sb" {
  name                = "acme-pack-sb"
  resource_group_name = "acme-rg"
  location            = "eastus"
  sku                 = "Standard"
  local_auth_enabled  = true              # ATL-333
  minimum_tls_version = "1.1"             # ATL-334
}

# --- Event Hub: SAS local auth on --------------------------------------------
# Fires ATL-335.
resource "azurerm_eventhub_namespace" "eh" {
  name                         = "acme-pack-eh"
  resource_group_name          = "acme-rg"
  location                     = "eastus"
  sku                          = "Standard"
  local_authentication_enabled = true     # ATL-335
}

# --- AI Search: RAG retrieval index reachable from the public internet -------
# Fires ATL-336.
resource "azurerm_search_service" "rag" {
  name                          = "acme-rag-search"
  resource_group_name           = "acme-rg"
  location                      = "eastus"
  sku                           = "standard"
  public_network_access_enabled = true    # ATL-336
}
