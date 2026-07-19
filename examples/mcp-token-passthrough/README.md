# MCP token-passthrough fixture

An MCP server wired to reuse the caller's inbound credential on its downstream
calls: its environment carries a forwarded `Authorization` header and the
caller's session cookie. Token passthrough breaks the token's audience binding,
defeats per-request authorization at the downstream API, and lets a compromised
or confused server replay the caller's identity. The MCP authorization spec
explicitly prohibits it.

```bash
attestral scan examples/mcp-token-passthrough
```

```
2 components · 1 finding · 1 high
```

## What fires, and why

| Server | Env | Rule | Risk |
|---|---|---|---|
| `api-gateway` | `HTTP_AUTHORIZATION`, `SESSION_COOKIE` | ATL-148 | Forwards the caller's token/cookie downstream instead of exchanging it for an audience-scoped credential. |
| `clean-tool` | *(none)* | *(none)* | Holds no forwarded credential. |

Distinct from ATL-104 (generic secret in env): those env keys carry no
`KEY`/`SECRET`/`TOKEN`/`PASSWORD` hint, so only the passthrough-specific rule
fires. A server holding its *own* downstream API key is ATL-104's job, not this.

## Research these checks are grounded in

- **OWASP MCP Top 10**: MCP01 Token Mismanagement & Secret Exposure - "do not
  pass through tokens." <https://owasp.org/www-project-mcp-top-10/>
- **MCP Security Best Practices (2025-11-25)**: an MCP server MUST NOT accept a
  token not issued for it and MUST NOT forward the client's token to a
  downstream service.
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
- **OWASP Top 10 for Agentic Applications (2026)**: ASI03 Privilege & Identity
  Abuse. **MITRE ATLAS**: AML.T0098 AI Agent Tool Credential Harvesting.
