# Intentionally insecure fixture for ATL-144: an AWS Bedrock AgentCore Runtime
# execution role still attached to the dev/quickstart full-access policy. Do
# not use as a template for real infrastructure.

resource "aws_iam_role" "agentcore_runtime" {
  name = "agentcore-runtime-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "bedrock-agentcore.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# ATL-144: the AgentCore starter toolkit's auto-generated policy, left attached
# past local development. Grants account-wide AgentCore actions, including
# GetWorkloadAccessTokenForUserId (mints a token for any caller-supplied user
# id, no IdP verification).
resource "aws_iam_role_policy_attachment" "agentcore_full_access" {
  role       = aws_iam_role.agentcore_runtime.name
  policy_arn = "arn:aws:iam::aws:policy/BedrockAgentCoreFullAccess"
}
