# Bedrock AgentCore IAM over-privilege fixture

An `aws_iam_role_policy_attachment` that leaves an AgentCore Runtime execution
role attached to `BedrockAgentCoreFullAccess`, the dev/quickstart policy the
AgentCore starter toolkit auto-generates.

```bash
attestral scan examples/agentcore-iam
```

Fires **ATL-144**: the policy grants broad, account-wide AgentCore actions,
including `GetWorkloadAccessTokenForUserId`, which mints a workload access
token from a caller-supplied user id with no identity-provider verification.
Left attached in production, a compromised agent runtime can mint tokens for
arbitrary users, not just act within the one workload it was deployed for.

The fix is to replace the managed policy with a role scoped to the exact
AgentCore resource ARNs the runtime needs, and to deny
`GetWorkloadAccessTokenForUserId` in favor of `GetWorkloadAccessTokenForJWT`
(which validates signature, issuer, and expiry) unless the agent genuinely has
no JWT available.

## Research

- **Unit 42, "Cracks in the Bedrock: Agent God Mode" (2026)**: the AgentCore
  starter toolkit's auto-create logic generates IAM roles scoped to the whole
  account rather than to individual resources; AWS updated its docs afterward
  to warn that the default role is for development only.
- **AWS managed policy reference - BedrockAgentCoreFullAccess**: confirms the
  policy includes `GetWorkloadAccessTokenForUserId`, documented as suitable
  for development and quickstart scenarios only.
