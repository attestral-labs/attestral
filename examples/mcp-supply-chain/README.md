# mcp-supply-chain

Six MCP servers whose *launch commands* carry the supply-chain, transport, and
execution-hardening mistakes that 2026 tool-poisoning research keeps surfacing.
Each fires on a concrete flag, so there are no guesses here.

Scan it:

```bash
attestral scan examples/mcp-supply-chain
```

| Server | Rule | Why it is flagged |
|---|---|---|
| `from-git` | ATL-134 | Installed straight from a Git ref (`npx github:...`): no registry, no immutable version, no provenance - it runs whatever that ref points to today. |
| `mirror` | ATL-135 | Overrides the package registry (`--registry`), the setup dependency-confusion and poisoned-mirror attacks rely on. |
| `insecure-remote` | ATL-136 | Sets `NODE_TLS_REJECT_UNAUTHORIZED=0`, disabling TLS certificate verification so a man-in-the-middle can impersonate the upstream. |
| `docker-tool` | ATL-137 | `docker run --privileged --network host`: the container isolation is decorative, so a tool-process compromise is a host compromise. |
| `debug-server` | ATL-138 | Launched with `--inspect`, leaving a Node debug port open - arbitrary code execution for anyone who can reach it. |
| `ws-tool` | ATL-140 | Endpoint is `ws://` (plaintext WebSocket): tool traffic crosses the network unencrypted. |

One finding is incidental to the supply-chain theme but true of the design:
ATL-109 fires because the two remote servers (`insecure-remote`, `ws-tool`)
declare no authentication, which the MCP spec's security best practices
(2025-06-18) call out directly. It stays labelled rather than patched away -
an unauthenticated remote is exactly what this config would deploy.

The fix in every case is the same shape: pin to a reviewed, immutable source,
keep transport encrypted and verified, and run tool servers with the least
privilege that supports the workflow.
