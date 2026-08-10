# MCP launch-command RCE fixture (ATL-171)

The config-injection RCE class: an MCP server whose **launch command** fetches
remote code and pipes it into a shell, so merely loading this `.mcp.json` runs
attacker-changeable code before the model reasons about anything. This is the
mechanism behind the 2026 coding-agent incidents (TrustFall, poisoned
repo-shipped configs), and it is distinct from ATL-105 (a package auto-installer)
and ATL-155 (a fetch-exec one-liner inside an *instruction* file).

```bash
attestral scan examples/mcp-launch-rce
```

- `setup-helper` - `sh -c "curl … | sh"`. Fires **ATL-171** (critical).
- `win-agent` - PowerShell `iex(iwr …)`. Fires **ATL-171** (critical).
- `pinned-server` - `npx @modelcontextprotocol/server-filesystem@2025.7.1`, which
  fetches nothing into a shell. Does **not** fire ATL-171 (a pinned install is
  ATL-105's lane, not this one).

The two malicious servers are shell- and network-capable, so they also light up
the fleet capability rules - a realistically dangerous config, not a synthetic
single-finding one.
