# Intentionally insecure GCP fixtures for the gcp_pack.yaml rule set
# (ATL-414..ATL-432). Every resource below is deliberately misconfigured to
# trigger a specific pack rule (or a small, disjoint set). Do not use as a
# template for real infrastructure.
#
# Attributes that would trip the core GCP rules (ATL-401..413) are intentionally
# omitted so this fixture exercises the pack in isolation.

# --- Compute Engine -------------------------------------------------------

# ATL-414 (OS Login off) + ATL-415 (serial port on) + ATL-416 (no Confidential
# VM) + ATL-417 (default Compute Engine service account). Scopes are narrow so
# the core cloud-platform rule (ATL-406) stays quiet.
resource "google_compute_instance" "agent_runner" {
  name         = "agent-runner"
  machine_type = "e2-standard-2"

  metadata = {
    enable-oslogin     = "FALSE"
    serial-port-enable = "TRUE"
  }

  confidential_instance_config {
    enable_confidential_compute = false
  }

  service_account {
    email  = "849302847-compute@developer.gserviceaccount.com"
    scopes = ["logging-write", "monitoring-write"]
  }
}

# --- Google Kubernetes Engine ---------------------------------------------

# ATL-418 (Binary Authorization off) + ATL-419 (intra-node visibility off) +
# ATL-420 (no Workload Identity) + ATL-421 (no release channel) + ATL-422
# (secrets not encrypted) + ATL-423 (legacy metadata endpoints exposed).
# enable_private_nodes / enable_shielded_nodes / enable_legacy_abac /
# issue_client_certificate are omitted so the core GKE rules stay quiet.
resource "google_container_cluster" "agents" {
  name        = "agents"
  location    = "us-central1"
  enable_intranode_visibility = false

  binary_authorization {
    evaluation_mode = "DISABLED"
  }

  release_channel {
    channel = "UNSPECIFIED"
  }

  database_encryption {
    state = "DECRYPTED"
  }

  node_config {
    metadata = {
      disable-legacy-endpoints = "false"
    }
  }
}

# --- Cloud SQL ------------------------------------------------------------

# ATL-424: point-in-time recovery disabled. No public IP / require_ssl attrs so
# the core Cloud SQL rules (ATL-402/403) stay quiet.
resource "google_sql_database_instance" "orders" {
  name             = "orders"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-custom-2-8192"
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = false
    }
  }
}

# ATL-433: automated backups disabled. PITR is left true so only ATL-433 fires
# (ATL-424 stays quiet); ip_configuration is omitted, mirroring "orders", so no
# core public-IP/SSL rule co-fires.
resource "google_sql_database_instance" "reports" {
  name             = "reports"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-custom-2-8192"
    backup_configuration {
      enabled                        = false
      point_in_time_recovery_enabled = true
    }
  }
}

# --- Cloud Storage --------------------------------------------------------

# ATL-425: public access prevention left inherited (not enforced).
# uniform_bucket_level_access is omitted so the core bucket rule (ATL-404)
# stays quiet.
resource "google_storage_bucket" "artifacts" {
  name                     = "acme-agent-artifacts"
  location                 = "US"
  public_access_prevention = "inherited"
}

# --- BigQuery -------------------------------------------------------------

# ATL-426: dataset shared with all authenticated users.
resource "google_bigquery_dataset_iam_member" "analytics_public" {
  dataset_id = "analytics"
  role       = "roles/bigquery.dataViewer"
  member     = "allAuthenticatedUsers"
}

# --- Cloud Functions ------------------------------------------------------

# ATL-427: HTTP function open to all ingress.
resource "google_cloudfunctions_function" "webhook" {
  name             = "webhook"
  runtime          = "python311"
  ingress_settings = "ALLOW_ALL"
  trigger_http     = true
}

# ATL-428: function invocable by anyone (unauthenticated).
resource "google_cloudfunctions_function_iam_member" "webhook_public" {
  cloud_function = "webhook"
  role           = "roles/cloudfunctions.invoker"
  member         = "allUsers"
}

# --- Cloud Run ------------------------------------------------------------

# ATL-429: service invocable by anyone (unauthenticated).
resource "google_cloud_run_service_iam_member" "api_public" {
  service  = "agent-api"
  location = "us-central1"
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# --- Cloud DNS ------------------------------------------------------------

# ATL-430: public zone with DNSSEC disabled.
resource "google_dns_managed_zone" "public" {
  name     = "acme-public"
  dns_name = "acme.example."

  dnssec_config {
    state = "off"
  }
}

# --- Project IAM ----------------------------------------------------------

# ATL-431: primitive Editor role granted at the project level.
resource "google_project_iam_member" "ci_editor" {
  project = "acme-prod"
  role    = "roles/editor"
  member  = "serviceAccount:ci@acme-prod.iam.gserviceaccount.com"
}

# --- Cloud KMS ------------------------------------------------------------

# ATL-432: crypto key usable by anyone. (Note: core ATL-413 also fires here via
# by_type prefix matching, since it has no rotation_period attribute.)
resource "google_kms_crypto_key_iam_member" "key_public" {
  crypto_key_id = "projects/acme-prod/locations/us/keyRings/main/cryptoKeys/data"
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "allUsers"
}
