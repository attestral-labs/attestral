# MCP Apps UI surface: connectDomains, permissions, extensions (SEP-1865)

MCP Apps (ext-apps spec 2026-01-26, SEP-1865) lets a server declare interactive
UI resources: a resource whose `_meta` carries the `io.modelcontextprotocol/ui`
object with CSP-style fields. `connectDomains` is egress the embedded UI is
*allowed* to perform (fetch/XHR targets; default `'none'`), `permissions` are
sandbox grants like `camera` and `clipboardWrite`. The MCP 2026-07-28 RC also
standardizes a declared extensions map (SEP-2663, `io.modelcontextprotocol/tasks`).

Four servers exercise the surface:

- **dash-widgets** - a UI panel whose CSP allows external egress
  (`https://telemetry.example.net`, wildcard `https://*.cdn-metrics.io`) and
  holds `camera` + `clipboardWrite` grants. Derives `_ui_connect_domains`,
  `_ui_external_connect`, `_ui_permissions`, `_ui_sensitive_permissions`, and
  the `ui_egress` capability token. Fires **ATL-160** (external connect
  domains) and **ATL-161** (sensor/clipboard permissions).
- **local-preview** - a UI resource with the default-safe CSP (`connectDomains`
  absent = `'none'`): derives *no* egress attribute, no `ui_egress` token, and
  fires nothing.
- **task-runner** - declares the tasks extension
  (`_declared_extensions = ["io.modelcontextprotocol/tasks"]`) but has no
  auto-approve list, so it fires nothing: background tasks alone are a
  feature, not a finding.
- **auto-pipeline** - declares the tasks extension *and* an `autoApprove`
  list, so long-running work executes with zero human checkpoints. Fires
  **ATL-162** (tasks + auto-approve) and **ATL-108** (auto-approve itself).

```bash
attestral scan examples/mcp-apps-ui
# 4 components · 4 findings · 1 critical · 1 high · 2 medium
```

The sibling fixture `examples/mcp-apps-ui-fleet/` pairs a UI-egress server
with a private-data server to exercise the fleet-level rule **ATL-220**; this
fixture deliberately has no private-data capability anywhere, so ATL-220 stays
silent here.

## Why declared UI egress is an agentic surface

An MCP App renders server-authored HTML inside the agent host. Its CSP is a
design-time declaration of everything that iframe may ever talk to, so an
external or wildcard `connectDomains` entry is an exfiltration channel that
exists even when the server *process* has no network capability at all: tool
results flow into the UI via the host bridge, and the UI is allowed to POST
them anywhere the CSP names. Sensitive sandbox grants (`camera`, `microphone`,
`geolocation`, clipboard write) let a server-authored surface collect data the
user handed to the *app*, never to the agent. Both are statically visible
before the app ever renders - exactly the review-before-install moment.

## Research

- **MCP Apps** (ext-apps spec 2026-01-26, SEP-1865): `io.modelcontextprotocol/ui`
  resource metadata, `connectDomains` / `resourceDomains` / `permissions`, and
  the default-deny (`'none'`) posture.
- **MCP 2026-07-28 RC** (SEP-2663): the standardized extensions map and the
  `io.modelcontextprotocol/tasks` key.
- **Backslash Security, July 2026**: the 2026-07-28 spec RC opens new
  endpoint-side attack surfaces - app UI egress among them - that gateway-side
  review of tool traffic cannot see.
- **OWASP-ASI09:2026** (a server-authored surface placed in front of the
  human, the same trust channel as elicitation),
  **OWASP-ASI02:2026** (tool misuse / exfiltration pairing), and
  **OWASP LLM02** (sensitive information disclosure via an allowed egress path).
