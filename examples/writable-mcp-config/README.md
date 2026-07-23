# World-writable MCP config (CVE-2026-30615 class)

A plain `.mcp.json` registering two boring, pinned stdio servers. The servers
are deliberately unremarkable - no shell, no secrets, no remote URL - because
the risk in this fixture is not in any server entry. It is in the **file**:
if the config (or its parent directory) is world-writable, any local user or
compromised process can rewrite it and swap a server's launch command for
their own binary, which the agent client then starts on every future session.

That is exactly how CVE-2026-30615 (Windsurf) turned a prompt injection into
persistence: the injected agent rewrote the local MCP config and
auto-registered a malicious stdio server. The static precondition - the
world-writable config - is what **ATL-163** flags, per server, since each
entry in a writable config is independently swappable.

```bash
attestral scan examples/writable-mcp-config
```

2 components · 0 findings

The clean result above is expected for a fresh checkout: the finding requires
the `o+w` permission bit on `.mcp.json`, and git cannot store that bit. The
test (`tests/test_writable_config_rule.py`) and the benchmark harness
(`evaluation/score.py`, via the `world_writable:` case setup) set the bit for
the duration of the scan and restore it, after which ATL-163 fires twice -
once for each server the writable file registers. Only world-write (`o+w`)
counts; a group-writable config is deliberately not flagged, because shared
staff-group setups (macOS default) would false-positive.

## The fix

`chmod o-w` the config file and its directory (owner-only is better), then
re-review the server list for entries you did not add - a writable config may
already have been tampered with.

## Research

- **CVE-2026-30615 (Windsurf)** - prompt injection gains persistence by
  rewriting the local MCP config to auto-register a malicious stdio server.
- **CWE-732** (incorrect permission assignment for critical resource),
  **NIST CM-5** (access restrictions for change), **OWASP Top 10 for Agentic
  Applications 2026 - ASI05** (unexpected code execution).
- Sibling rule: **ATL-113** (world-writable agent-instruction file) - same
  threat shape, one rung weaker: a writable instruction file steers what the
  agent is told; a writable config swaps what launches.
