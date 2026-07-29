# credential-concentration

One MCP server that is an LLM gateway, holding standing API keys for five
providers at once (`llm-gateway`: OpenAI, Anthropic, Gemini, AWS, Groq), next to
a normal single-provider server (`notes`: Notion). It is the architecture behind
the March 2026 LiteLLM supply-chain incident, where one process holding dozens of
providers' keys turned a single compromise into an estimated 500,000 leaked
identities.

The point of the fixture is the contrast: `ATL-164` fires on the gateway and is
silent on `notes`, so it keys on credential *concentration* (four or more
distinct providers in one process), not on any single secret. That is the
blast-radius the CB4A draft (`draft-hartman-credential-broker-4-agents-00`) rates
CRITICAL under threat TM-1, and the reason a credential broker exists: so an
agent process never holds a reusable, agent-readable key.

```
2 components · 7 findings · 5 high · 2 medium
```

The fix is not to add another secret scanner. It is to front the providers with a
credential broker (CB4A Model A/B, for example agentgateway or Vault) that injects
a short-lived, scoped token per call, so the process holds no reusable key, or at
minimum to split the providers across isolated processes so one compromise does
not inherit them all.
