# The role the agent runtime assumes is scoped to exactly what it needs - a
# read on one bucket, no wildcard, no AdministratorAccess. ATL-218 must not
# fire: the agent->cloud join exists, but the cloud grant is not admin.
resource "aws_iam_role" "agent_task_role" {
  name = "agent_task_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE" }
      Action    = "sts:AssumeRoleWithWebIdentity"
    }]
  })
}

resource "aws_iam_role_policy" "agent_scoped" {
  name = "agent-scoped"
  role = aws_iam_role.agent_task_role.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::agent-inbox/*"
    }]
  })
}
