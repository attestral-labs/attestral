# Tool parameter mapped to a raw transport header (SEP-2243)

MCP SEP-2243 (Final) lets a tool's input schema mark a parameter with
`x-mcp-header`, and a conforming client then mirrors the model-chosen argument
value into an `Mcp-Param-{Name}` HTTP header on every `tools/call`. This
server's `query_metrics` tool maps `tenant_id`:

```json
"tenant_id": {
  "type": "string",
  "description": "The tenant identifier.",
  "x-mcp-header": "TenantId"
}
```

```bash
attestral scan examples/header-mapped-params
# 1 component · 1 finding · 1 medium   (ATL-158)
```

## Why a header mapping is an agentic finding

Load balancers, WAFs, rate limiters, and authorization gateways act on
`Mcp-Param-TenantId` *before* the server validates anything - and the value
originates from the model, so a prompt injection steering the agent chooses it
too. SEP-2243's own security section spells the risk out:

- intermediaries "MUST NOT treat these values as trusted input" for
  security-sensitive decisions;
- tenant ids / region names in headers "MUST be independently verified against
  the authenticated user's permissions";
- sensitive parameters (tokens, PII) "SHOULD NOT" be header-mapped at all,
  since every intermediary and log on the path sees them.

A tenant id mapped to a routing header is exactly the spoofing case the SEP
warns about: route to a less-secured tenant path, bypass per-tenant rate
limits, or leak the identifier along the way. The `metric` parameter carries no
`x-mcp-header` and derives nothing - an ordinary schema never fires.

## Research

- **MCP SEP-2243** (HTTP Header Standardization, Final 2026): the
  `x-mcp-header` extension, its security-implications section, and the
  header/body mismatch rejection requirement (`HeaderMismatch`).
- **CWE-644** (Improper Neutralization of HTTP Headers) / **NIST SI-10**
  (information input validation).
- **OWASP-ASI02:2026** (untrusted model output driving downstream systems).
