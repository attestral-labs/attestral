# The IAM role the agent runtime assumes via IRSA. It is granted full
# AdministratorAccess through a managed-policy attachment - the common
# real-world admin grant, and no policy-document parsing is required.
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

resource "aws_iam_role_policy_attachment" "agent_admin" {
  role       = aws_iam_role.agent_task_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# FP guard: a break-glass admin role with the very same AdministratorAccess
# attachment that NO ServiceAccount references. It is over-privileged in
# isolation, but no agent runtime assumes it, so ATL-218 must stay silent on
# it - the rule fires only on the agent->cloud join, never on a lone role.
resource "aws_iam_role" "breakglass_admin" {
  name = "breakglass_admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::123456789012:root" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "breakglass_admin" {
  role       = aws_iam_role.breakglass_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
