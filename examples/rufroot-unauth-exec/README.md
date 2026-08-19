# Unauthenticated network-exposed exec server (ATL-176 - the RufRoot class)

Remote unauthenticated RCE, the strongest agentic finding there is: an MCP
server that is **reachable over the network**, has **no authentication**, and
**grants command execution**. That conjunction is the RufRoot vulnerability
(CVE-2026-59726, CVSS 10.0; also LibreChat CVE-2026-22252) - an MCP bridge bound
to the network by default that exposes a `terminal_execute` tool with no token,
header check, or IP allowlist, so a single unauthenticated HTTP request runs
arbitrary commands, steals the model API keys, and poisons the agent's memory.

No single field is the finding. A per-config linter reading one line sees an
ordinary remote endpoint, or an ordinary shell wrapper, and stays quiet. Only
Attestral's system model, which composes the **transport**, the **missing
authentication**, and the **execution capability** on one server, sees the open
door - which is why ATL-176 fires on exactly one of the four servers below.

```bash
attestral scan examples/rufroot-unauth-exec
```

4 components · 9 findings · 4 critical · 5 high

- `ops-bridge` - bash-launched exec bridge, reachable at a plaintext `http://`
  endpoint with no auth. All three legs present, so it fires **ATL-176**
  (critical) on top of its constituent findings (ATL-103 shell, ATL-101
  non-TLS, ATL-109 remote-unauthed).

The other three servers each drop exactly one leg, so ATL-176 stays silent -
the precision boundary the conjunction buys:

- `local-terminal` - shell-capable but **stdio-only** (no `url`), so it is not
  network-reachable. Fires ATL-103; **not** ATL-176.
- `docs-remote` - unauthenticated and network-reachable, but **read-only** (no
  execution capability). Fires ATL-101 + ATL-109; **not** ATL-176.
- `authed-bridge` - shell-capable and network-reachable, but **requires a
  bearer token**, so it is authenticated. Fires ATL-103 + ATL-101 (a token over
  plaintext HTTP is still a non-TLS problem); **not** ATL-109 or ATL-176.
