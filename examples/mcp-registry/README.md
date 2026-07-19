# MCP Registry manifest fixture

A `server.json` of the kind the official MCP registry publishes (schema
2025-12-11). Attestral reads it as its own surface: a *published* server declares
its packages, secret variables, and transports here, so secret-handling mistakes
and deprecated transports are visible before anyone installs it.

```bash
attestral scan examples/mcp-registry
```

## What fires, and why

| Declaration | Rule | Risk |
|---|---|---|
| `DATA_BRIDGE_API_KEY` has a literal `value` (and `isSecret: true`) | ATL-131 | A credential baked into the manifest ships to everyone who installs the server from the registry. |
| `DATABASE_PASSWORD` is secret-named but has no `isSecret` | ATL-132 | Clients, logs, and the registry treat it as ordinary config and never redact it. |
| `remotes[].type: sse` / `websocket` | ATL-133 | HTTP+SSE was deprecated (SEP-2596) for streamable-http, and the early WebSocket transport was dropped for weak origin validation (CVE-2026-59950); current-spec clients drop both and can no longer reach the server. |
| `LOG_LEVEL` (has a value, not secret-named) | *(none)* | Ordinary config: the secret rules deliberately stay silent. |

The manifest surface is net-new territory: no client `mcp.json` carries these
`isSecret` flags or the registry transport list.

## Research these checks are grounded in

- **MCP Registry `server.json` schema** (2025-12-11): `environmentVariables` and
  remote `headers` carry `isSecret` / `isRequired` / `value`; transports are
  `stdio`, `streamable-http`, `sse`.
  <https://github.com/modelcontextprotocol/registry/blob/main/docs/reference/server-json/generic-server-json.md>
- **MCP spec draft changelog** (SEP-2596): HTTP+SSE transport deprecated.
  <https://modelcontextprotocol.io/specification/draft/changelog>
- **NSA CSI, "MCP Security Design Considerations for AI-Driven Automation"**
  (05/2026): align tools to data classification, keep credentials out of shipped
  artifacts. **OWASP MCP Top 10**: MCP01 Token Mismanagement & Secret Exposure,
  MCP04 Supply Chain & Dependency Tampering.
  <https://owasp.org/www-project-mcp-top-10/>
