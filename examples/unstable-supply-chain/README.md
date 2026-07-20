# Unstable supply chain: a pre-release channel and a debug port

Two launch-surface problems in one fleet:

- `beta-tools` is pinned to `@example/tools-mcp@beta` - a **pre-release channel**,
  not an immutable version. What runs is whatever `@beta` serves today.
- `debug-fs` is launched `node --inspect=0.0.0.0:9229 server.js` - a **remote
  debugging port** bound to all interfaces, an arbitrary-code-execution foothold
  for anything that can reach it.

```bash
attestral scan examples/unstable-supply-chain
```

- **ATL-153** (medium) fires on the pre-release channel. It is the sibling of
  ATL-106 (`@latest`): a mutable/rolling channel is a rug-pull surface, and
  pre-release code carries less review. A pinned `@1.2.3` does not fire.
- **ATL-154** (high) fires on the inspector port. A debugger left in a committed
  launch command sidesteps every capability constraint the reviewed design placed
  on the tool. A plain `node server.js` does not fire.

## The fix

Pin the tool server to an immutable released version or digest, and remove the
`--inspect` flag from the committed command (enable a debugger only interactively,
bound to loopback).

## Research

- **OWASP-ASI04:2026** (Agentic Supply Chain), **ASI05:2026** (Unexpected Code
  Execution); **CWE-494** (download of code without integrity check), **CWE-489**
  (active debug code).
