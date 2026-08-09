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
8 components · 4 findings · 1 high · 3 medium
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
  **ATL-073** (medium).

Attribute names are the terraform-flattened leaves of the hashicorp/aws
`bedrockagentcore_*` resources, so no ingester change was needed - the whole wave
is data rules over the model the Terraform ingester already builds.
