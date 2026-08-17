# Workspace-autoload MCP config fixture

A `.cursor/mcp.json` committed inside the repository. When a developer opens or
"trusts" this workspace in Cursor (or the same file under `.amazonq/` in Amazon
Q, `.vscode/` in VS Code, or a project `.claude/` config), the IDE launches the
declared stdio server automatically - before anyone reviews the command it runs.
Cloning an untrusted repo then runs an attacker-planted local process in the
developer's session. This is the "MCP auto-load on workspace trust" attack
surface behind the July 2026 Cursor and Amazon Q incidents.

```bash
attestral scan examples/workspace-autoload
```

1 component · 1 finding · 1 high

Fires **ATL-174**: the server is a stdio launch (`command`/`args`, not a plain
remote `url`) declared in a project-trust IDE directory, so opening the repo
auto-runs it. The rule is deliberately narrow:

- A user-**global** copy of the same file (`~/.cursor/mcp.json`, or a config
  under an OS app-config root) is one the developer installed for themselves,
  not one a repo can plant - it does **not** fire.
- A repo-root `.mcp.json` (the widely-shared team convention whose host prompts
  for approval on open) does **not** fire - a trust checkpoint already exists.
- A **remote-`url`-only** entry launches no local process and does **not** fire.

Remediation: don't ship auto-launching MCP servers in repo IDE configs; keep
only authenticated remote `url` servers there, and gate any local launch behind
an explicit reviewed opt-in.
