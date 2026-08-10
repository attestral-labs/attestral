# GCP Vertex AI agent-runtime hardening fixture. Each `_weak` resource trips one
# ATL-43x rule; the `_hardened` counterpart sets a customer-managed key and stays
# silent, so the fixture pins precision, not just recall.

# --- ATL-435: reasoning engine (agent runtime) without CMEK -----------------
resource "google_vertex_ai_reasoning_engine" "shipping_weak" {
  display_name = "shipping-agent"
  region       = "us-central1"
  spec {
    service_account = "shipping-agent@my-proj.iam.gserviceaccount.com"
  }
}

resource "google_vertex_ai_reasoning_engine" "shipping_hardened" {
  display_name = "billing-agent"
  region       = "us-central1"
  spec {
    service_account = "billing-agent@my-proj.iam.gserviceaccount.com"
  }
  encryption_spec {
    kms_key_name = "projects/my-proj/locations/us-central1/keyRings/agents/cryptoKeys/reasoning"
  }
}

# --- ATL-436: endpoint (model serving surface) without CMEK -----------------
resource "google_vertex_ai_endpoint" "serving_weak" {
  name         = "agent-endpoint"
  display_name = "agent-endpoint"
  location     = "us-central1"
}

resource "google_vertex_ai_endpoint" "serving_hardened" {
  name         = "agent-endpoint-cmek"
  display_name = "agent-endpoint-cmek"
  location     = "us-central1"
  encryption_spec {
    kms_key_name = "projects/my-proj/locations/us-central1/keyRings/agents/cryptoKeys/serving"
  }
}
