# Bedrock AgentCore agent-to-cloud admin join (ATL-218, the AWS-native path).
# The agent runtime's execution role_arn resolves to an AdministratorAccess role,
# so any injection inside the runtime inherits full control of the account. The
# scoped gateway alongside it (a read-only role) proves the join fires only on the
# admin grant, not on any AgentCore resource that happens to name a role.

# --- admin path: fires ATL-218 ---
resource "aws_iam_role" "agentcore_admin_role" {
  name = "agentcore_admin_role"
}

resource "aws_iam_role_policy_attachment" "agent_admin" {
  role       = aws_iam_role.agentcore_admin_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_bedrockagentcore_agent_runtime" "shipping" {
  agent_runtime_name = "shipping-agent"
  role_arn           = aws_iam_role.agentcore_admin_role.arn
  network_configuration {
    network_mode = "VPC"
    network_mode_config {
      subnets         = ["subnet-0a1b2c3d"]
      security_groups = ["sg-0a1b2c3d"]
    }
  }
}

# --- scoped path: silent (read-only role, not admin) ---
resource "aws_iam_role" "gw_scoped" {
  name = "agentcore_gateway_role"
}

resource "aws_iam_role_policy_attachment" "gw_scoped" {
  role       = aws_iam_role.gw_scoped.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
}

resource "aws_bedrockagentcore_gateway" "tools" {
  name            = "shipping-tools"
  role_arn        = aws_iam_role.gw_scoped.arn
  authorizer_type = "CUSTOM_JWT"
  authorizer_configuration {
    custom_jwt_authorizer {
      allowed_clients = ["shipping-agent-client-id"]
    }
  }
  policy_engine_configuration {
    mode = "ENFORCE"
    arn  = "arn:aws:bedrock-agentcore:us-west-2:111122223333:policy-engine/pe"
  }
}
