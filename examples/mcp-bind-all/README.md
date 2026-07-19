# MCP bind-all-interfaces fixture

A local MCP server launched so it listens on `0.0.0.0` instead of loopback.
Once bound to every interface, a tool server meant for one agent is an
unauthenticated endpoint for the whole LAN, and a malicious web page can reach
it through DNS rebinding to drive its tools.

```bash
attestral scan examples/mcp-bind-all
```

```
3 components · 1 finding · 1 high
```

## What fires, and why

| Server | Launch | Rule | Risk |
|---|---|---|---|
| `metrics-server` | `--host 0.0.0.0 --port 9090` | ATL-147 | Bound to all interfaces: reachable off-host and abusable via DNS rebinding. |
| `local-notes` | `--host 127.0.0.1` | *(none)* | Loopback-only: not exposed. |
| `stdio-lint` | stdio (no host) | *(none)* | No network listener at all. |

The rule fires only on the explicit `0.0.0.0` token, never on absence, so a
loopback or stdio server is silent.

## Research these checks are grounded in

- **DNS-rebinding / local-server exposure of MCP servers**: CVE-2026-59950,
  CVE-2026-63118, CVE-2025-66416, CVE-2026-23744.
- **OWASP MCP Top 10**: MCP07 Insecure Server Deployment & Transport.
  <https://owasp.org/www-project-mcp-top-10/>
- **OWASP Top 10 for Agentic Applications (2026)**: ASI05 Unexpected Code
  Execution. **MITRE ATLAS**: AML.T0049 Exploit Public-Facing Application.
- **MCP Security Best Practices (2025-11-25)**: bind local servers to loopback
  and validate the `Origin`/`Host` header.
  <https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices>
