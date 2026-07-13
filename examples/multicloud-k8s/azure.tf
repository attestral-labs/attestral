# Intentionally insecure Azure fixtures for Attestral rule coverage.

resource "azurerm_storage_account" "public" {
  name                            = "acmepublicdata"
  enable_https_traffic_only       = false
  allow_nested_items_to_be_public = true

  network_rules {
    default_action = "Allow"
  }
}

resource "azurerm_mssql_server" "db" {
  name                          = "acme-sql"
  public_network_access_enabled = true
}

resource "azurerm_network_security_rule" "open_ssh" {
  name                       = "allow-all-ssh"
  access                     = "Allow"
  direction                  = "Inbound"
  protocol                   = "Tcp"
  destination_port_range     = "22"
  source_address_prefix      = "*"
  destination_address_prefix = "*"
}

resource "azurerm_key_vault" "vault" {
  name                     = "acme-kv"
  purge_protection_enabled = false
}

resource "azurerm_postgresql_server" "pg_single" {
  name                     = "acme-pg"
  ssl_enforcement_enabled  = false                # ATL-307
}

resource "azurerm_mysql_server" "mysql_single" {
  name                     = "acme-mysql"
  ssl_enforcement_enabled  = false                # ATL-308
}

# --- Additional insecure fixtures for ATL-309..316 ---

resource "azurerm_storage_account" "coldstore" {
  name                              = "acmecoldstore"
  infrastructure_encryption_enabled = false     # ATL-309
  min_tls_version                   = "TLS1_0"   # ATL-310
}

resource "azurerm_key_vault" "public_vault" {
  name                          = "acme-kv-public"
  public_network_access_enabled = true           # ATL-311
}

resource "azurerm_mssql_database" "appdb" {
  name                                = "acme-appdb"
  transparent_data_encryption_enabled = false    # ATL-312
}

resource "azurerm_linux_web_app" "api" {
  name       = "acme-api"
  https_only = false                              # ATL-313
}

resource "azurerm_linux_virtual_machine" "jump" {
  name                            = "acme-jump"
  disable_password_authentication = false         # ATL-314
}

resource "azurerm_kubernetes_cluster" "aks" {
  name                  = "acme-aks"
  local_account_enabled = true                    # ATL-315
}

resource "azurerm_postgresql_flexible_server" "pg" {
  name                          = "acme-pg-flex"
  public_network_access_enabled = true            # ATL-316
}
