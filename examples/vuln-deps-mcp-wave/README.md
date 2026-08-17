# Vulnerable MCP-server dependency fixture (2026 CVE wave)

A `requirements.txt` and a `package.json` that pin MCP-server packages to
versions with published CVEs. Like `examples/vulnerable-deps`, the vulnerability
lives in the agent's dependency tree, not in any MCP or cloud config an ingester
reads - the surface a design-time architecture review usually misses.

```bash
attestral scan examples/vuln-deps-mcp-wave
```

4 components · 4 findings · 4 critical

Fires **ATL-145** four times:

- `mcp-server-kubernetes==3.8.9` (npm) - CVE-2026-61459 (CVSS 9.8), argument
  injection: a leading-dash resourceType/name injects `--server` into kubectl
  and exfiltrates the caller's bearer token. Fixed in 3.9.0.
- `open-webui==0.8.11` - CVE-2026-45672, `/api/v1/utils/code/execute` runs
  attacker Python even when `ENABLE_CODE_EXECUTION=false`. Fixed in 0.8.12.
- `excel-mcp-server==0.1.7` - CVE-2026-40576, unauthenticated path traversal
  over the SSE / streamable-HTTP transport (arbitrary host file read/write).
  Fixed in 0.1.8.
- `aws-mcp==1.7.0` - CVE-2026-5059 (CVSS 9.8), unauthenticated command-injection
  RCE. No fixed release exists, so the remediation is removal, not upgrade.

`requests==2.32.0` is a negative control: not in the known-CVE table, so it must
not flag. Only an exactly pinned (`==` / exact npm) vulnerable version fires; an
open range is left alone, so the false-positive rate stays near zero.
