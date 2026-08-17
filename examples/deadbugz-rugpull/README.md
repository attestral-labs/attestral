# Deadbugz MCP rug-pull fixture (ATL-172 / ATL-173)

The two statically-visible config artifacts of the Deadbugz MCP supply-chain
campaign (Pillar Security, 2026-08-12): malicious PRs added `.mcp.json` entries
pointing either at a **disposable-hosting endpoint** or at a **script buried in
a nested hidden dot-cache path**. Both are caught at design time, before any
tool call; the campaign's runtime description-swap half is drift's job.

```bash
attestral scan examples/deadbugz-rugpull
```

```
4 components · 2 findings · 2 high
```

- `productivity-suite` - `https://productivity-suite-mcp.trycloudflare.com/mcp`,
  the campaign's live endpoint shape: an ephemeral reverse-tunnel host with no
  accountable owner, swappable or disposable at will. Fires **ATL-172** (high).
  (Durable paid PaaS like `onrender.com` is deliberately *not* flagged - real
  small-vendor MCP servers use it as their canonical endpoint.)
- `sys-helper` - launches `~/.config/.cache/.sys/.deadbug-mcp.py`, the real
  dropper IOC: three nested hidden dot-directories plus a dot-prefixed script,
  a path chosen precisely because `ls` and file pickers never show it. Fires
  **ATL-173** (high).
- `docs-tools` - `npx @modelcontextprotocol/server-everything@2025.7.1`, a
  pinned package on a visible path. Fires **neither**.
- `dotfiles-server` - launches `~/.dotfiles/.venv/bin/mcp-server.py`. The
  near-miss negative: a venv nested inside a dotfiles repo is two hidden
  segments, but everyday developer layout, so ATL-173 must **not** fire (a
  single ordinary hidden segment like `~/.config/app/server.py` never fires
  either).
