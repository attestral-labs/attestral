# MCP Apps UI fleet: private data paired with an iframe's own egress

Two servers that are each defensible alone and toxic together:

- **project-files** - `@modelcontextprotocol/server-filesystem` scoped to a
  single project directory (`/srv/projects/reports`). Private-data access,
  narrowly rooted: no per-server finding.
- **report-widgets** - ships an MCP App (ext-apps spec 2026-01-26, SEP-1865)
  whose CSP declares an external connect origin
  (`https://ingest.chart-metrics.io`). Fires **ATL-160** on its own: the host
  must grant that iframe standing fetch/XHR egress where the spec defaults to
  `connect-src 'none'`.

Together they complete an exfiltration pairing only the assembled system
model can see, and the fleet-level rule fires:

- **ATL-220** - the fleet combines a private-data capability (`filesystem`)
  with the `ui_egress` capability token. Tool results from the filesystem
  server flow into the rendered UI over the host bridge, and the UI is allowed
  to POST them to the origins its CSP names. The private-data server and the
  UI-declaring server are *different* servers, so an egress review of tool
  traffic - or any per-server linter - never sees the pairing: the filesystem
  server has no network capability, and the widgets server reads no files.

```bash
attestral scan examples/mcp-apps-ui-fleet
# 2 components · 2 findings · 2 high
```

The sibling fixture `examples/mcp-apps-ui/` holds the per-server UI checks
(ATL-160/161/162) and the negative case: UI egress with no private-data
capability anywhere must *not* fire ATL-220.

## Research

- **MCP Apps** (ext-apps spec 2026-01-26, SEP-1865): `connectDomains` maps to
  the CSP `connect-src` directive and defaults to `'none'`.
- **Backslash Security, July 2026**: the 2026-07-28 spec RC's app surfaces are
  endpoint-side channels that gateway review of tool traffic cannot see.
- **The lethal trifecta** (Willison 2025) / **OWASP-ASI02:2026**: private data
  plus an outbound channel plus injected instructions; here the outbound
  channel is the UI iframe's CSP, not a tool.
