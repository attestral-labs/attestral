# Amazon Bedrock AgentCore hardening fixture

Terraform for the AWS agent-runtime moat: the agent's own hosting, its tool
gateway, its memory store, and the Cedar policy engine that authorizes its tool
calls. Each `*_weak` resource trips one rule; each `*_hardened` counterpart is
the correct form and stays silent, so the fixture pins precision, not just
recall.

```bash
attestral scan examples/agentcore-hardening
```

```
10 components · 6 findings · 3 high · 3 medium
```

- `aws_bedrockagentcore_agent_runtime.shipping_weak` - `network_mode = "PUBLIC"`,
  so the credential-holding agent runs on public infrastructure. Fires
  **ATL-070** (high). The `_hardened` runtime uses `network_mode = "VPC"`.
- `aws_bedrockagentcore_memory.notes_weak` - no `encryption_key_arn`, so agent
  memory (where injected instructions and exfiltrated data persist) is encrypted
  only with an AWS-managed key. Fires **ATL-071** (medium).
- `aws_bedrockagentcore_policy.guard_weak` - `validation_mode =
  "IGNORE_ALL_FINDINGS"`, so a malformed Cedar policy is accepted rather than
  rejected. Fires **ATL-072** (medium).
- `aws_bedrockagentcore_gateway.tools_weak` - `policy_engine_configuration.mode =
  "LOG_ONLY"`, so tool-call policies are evaluated but never enforced. Fires
  **ATL-073** (medium). It also authenticates with a custom JWT authorizer but
  names no `allowed_clients`, so any client of its issuer can invoke every tool -
  fires **ATL-074** (high). The `_hardened` gateway sets `allowed_clients` and
  `mode = "ENFORCE"`.

- `aws_bedrockagentcore_gateway_target.crm_weak` - routes to a remote MCP server
  (`https://crm.partner-saas.example/mcp`) with `gateway_iam_role {}` and no
  scoped credential provider, so the gateway forwards its own IAM identity to a
  third-party endpoint. Fires **ATL-075** (high). The `_hardened` target reaches
  the same endpoint through a scoped `oauth` provider (`provider_arn`) and stays
  silent.

Most attributes are the terraform-flattened leaves of the hashicorp/aws
`bedrockagentcore_*` resources; ATL-074 and ATL-075 add two small
`_derive_agentcore` post-passes (the JWT allowlist and the remote-target
credential check), since their signals are compound.
