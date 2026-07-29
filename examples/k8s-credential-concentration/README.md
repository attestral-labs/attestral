# k8s-credential-concentration

A Kubernetes Deployment running a LiteLLM-class LLM gateway whose container env
sources standing API keys for five providers at once (`litellm`: OpenAI,
Anthropic, Gemini, Groq, Mistral), next to a single-provider sidecar (`notes`:
Notion) in the same pod.

This is the deployment-manifest counterpart to
[`credential-concentration`](../credential-concentration/README.md). A holistic
sweep of 390 popular MCP repositories found the concentration pattern in **zero**
committed `.mcp.json` files, because committed configs do not ship provider keys
in env. They ship here, in the Deployment that actually runs. `ATL-165` catches
the gateway container and stays silent on the sidecar, so it keys on credential
*concentration* (four or more distinct providers in one workload), not on any
single secret, the CB4A TM-1 blast radius.

```
3 components · 17 findings · 1 high · 10 medium · 6 low
```

The fix is the same as the MCP layer: front the providers with a credential
broker (CB4A Model A/B, for example agentgateway or Vault) that injects a
short-lived, scoped token per call so the pod holds no reusable key, and split
the providers across isolated workloads so one compromise does not inherit them
all. Note the keys are already sourced from `secretKeyRef` (the good pattern for
storage) - the finding is about *concentration*, which a secret store does not
address.
