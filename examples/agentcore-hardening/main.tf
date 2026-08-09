# Amazon Bedrock AgentCore hardening fixture.
# The four `*_weak` resources each trip one ATL-07x rule; the `*_hardened`
# counterparts are the correctly-configured form and must stay silent, so the
# fixture pins precision, not just recall.

# --- ATL-070: agent runtime on the public network ---------------------------
resource "aws_bedrockagentcore_agent_runtime" "shipping_weak" {
  agent_runtime_name = "shipping-agent"
  role_arn           = "arn:aws:iam::111122223333:role/shipping-agent"
  network_configuration {
    network_mode = "PUBLIC"
  }
}

resource "aws_bedrockagentcore_agent_runtime" "shipping_hardened" {
  agent_runtime_name = "billing-agent"
  role_arn           = "arn:aws:iam::111122223333:role/billing-agent"
  network_configuration {
    network_mode = "VPC"
    network_mode_config {
      subnets         = ["subnet-0a1b2c3d"]
      security_groups = ["sg-0a1b2c3d"]
    }
  }
}

# --- ATL-071: memory store without a customer-managed key -------------------
resource "aws_bedrockagentcore_memory" "notes_weak" {
  name                  = "agent-memory"
  event_expiry_duration = 90
}

resource "aws_bedrockagentcore_memory" "notes_hardened" {
  name                  = "agent-memory-cmk"
  event_expiry_duration = 90
  encryption_key_arn    = "arn:aws:kms:us-west-2:111122223333:key/abcd-1234"
}

# --- ATL-072: Cedar policy with validation disabled -------------------------
resource "aws_bedrockagentcore_policy" "guard_weak" {
  policy_engine_id = "pe-shipping"
  validation_mode  = "IGNORE_ALL_FINDINGS"
  definition {
    cedar {
      statement = "permit(principal, action, resource);"
    }
  }
}

resource "aws_bedrockagentcore_policy" "guard_hardened" {
  policy_engine_id = "pe-billing"
  validation_mode  = "FAIL_ON_ANY_FINDINGS"
  definition {
    cedar {
      statement = "permit(principal, action, resource);"
    }
  }
}

# --- ATL-073: gateway policy engine in log-only mode ------------------------
resource "aws_bedrockagentcore_gateway" "tools_weak" {
  name            = "shipping-tools"
  role_arn        = "arn:aws:iam::111122223333:role/shipping-gw"
  authorizer_type = "CUSTOM_JWT"
  policy_engine_configuration {
    mode = "LOG_ONLY"
    arn  = "arn:aws:bedrock-agentcore:us-west-2:111122223333:policy-engine/pe-shipping"
  }
}

resource "aws_bedrockagentcore_gateway" "tools_hardened" {
  name            = "billing-tools"
  role_arn        = "arn:aws:iam::111122223333:role/billing-gw"
  authorizer_type = "CUSTOM_JWT"
  policy_engine_configuration {
    mode = "ENFORCE"
    arn  = "arn:aws:bedrock-agentcore:us-west-2:111122223333:policy-engine/pe-billing"
  }
}
