# Agent trust + supply-chain signals (ATL-141/142/143)

Three surfaces a system model reads that a config-by-config scanner does not
connect: the agent's own settings, its A2A card, and the registry manifest it
publishes. Each carries one standing-risk default.

```bash
attestral scan examples/agent-supply-trust
```

```
3 components · 3 findings · 2 high · 1 medium
```

| Rule | Severity | The planted default |
|---|---|---|
| ATL-141 | high | `.claude/settings.json` `allow` includes `Bash(*)`: unrestricted command execution, pre-approved for anyone who opens the repo. |
| ATL-143 | high | The published `server.json` pins a package to `latest`: whoever installs gets whatever the registry serves that day (a registry-layer rug-pull). |
| ATL-142 | medium | The A2A card requires auth, but with a static `apiKey` instead of short-lived OAuth tokens: a leaked key is a standing compromise. |

Each is precise, not a catch-all: a scoped `Bash(git status)` allow, an OAuth
scheme, and an exact `1.4.2` version pin all pass clean. The signals are derived
in the ingesters (`_permissive_allow`, `_weak_auth_scheme`, `_has_mutable_pin`),
so the rules stay pure data.

## Grounding

- **OWASP Top 10 for Agentic Applications 2026** - ASI03 Identity & Privilege
  Abuse, ASI04 Agentic Supply Chain, ASI05 Unexpected Code Execution.
- **OWASP MCP Top 10 2025** - MCP04 (supply chain), MCP07 (transport/auth).
- **OAuth 2.0 (RFC 6749)** for the short-lived-token recommendation; **NIST**
  AC-6, IA-5, CM-2.
