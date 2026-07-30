# Over-broad filesystem root fixture

Two filesystem MCP servers, identical except for the directory they are granted.
This fixture exists to pin the **precision** of `ATL-102`: the over-broad grant
fires, the correctly-scoped one does not.

```bash
attestral scan examples/overbroad-fs-root
```

- `home-files` is rooted at `/Users/dev` - the developer's **home directory
  itself**, so the agent (and any prompt injection that reaches it) can read
  `~/.ssh`, `~/.aws/credentials`, browser data, and every other project. Fires
  **ATL-102**.
- `project-files` is rooted at `/Users/dev/acme-app` - a **specific project
  subdirectory**, the correct way to scope a filesystem server. It classifies as
  `project` and does **not** fire ATL-102.

The distinction is the whole point: the grant scope, not the presence of a path,
is the risk. `ATL-102`'s earlier bare-prefix matcher flagged any argument under
`/Users` or `/home`, which false-positived on every developer who scoped a
server to their actual repo. The ingester now classifies the broadest grant as
`root` / `system` / `home` / `project`, and only the first three fire. Both
servers are pinned to the fixed `2025.7.1` so the CVE table (`ATL-117`) stays out
of the picture and this fixture demonstrates one thing.
