# Trust-asymmetry shadowing: a collision is worse when one side is untrusted

A tool-name collision between two equally-trusted first-party servers is usually
a config mistake. The same collision between a trusted server and a lower-trust
one is the shadowing attack itself: the lower-trust server can answer the calls
the agent believes go to the trusted tool.

This fixture runs two servers that both expose `create_issue`:

- `linear` is pinned to an exact version (`@linear/mcp-server@1.2.3`).
- `notes-helper` tracks a mutable tag (`notes-helper-mcp@latest`), so its code
  can change under you after review - a rug-pull surface (ATL-106).

```bash
attestral scan examples/tool-shadowing-trust
```

`ATL-204` fires for the collision, and the trust-asymmetry pass then **raises it
from high to critical**, naming the lower-trust shadower:

```
ATL-204  Tool name exposed by more than one MCP server  (raised from high)
   ... Trust asymmetry: the colliding servers are not equally trusted -
   lower-trust server(s) notes-helper (mutable @latest pin) can shadow a tool
   a more-trusted server owns.
```

The paired control is [`tool-shadowing`](../tool-shadowing), where both servers
are pinned: the collision is symmetric, so it stays at `ATL-204`'s base severity
and is not escalated. The pass raises severity on the asymmetry, not on the
collision alone, so it never inflates an ordinary two-server name clash.

## The signals

A server is treated as lower-trust when its launch identity is mutable or
unverified: a mutable `@latest` / `:latest` tag (ATL-106), a remote
unauthenticated endpoint, or a known-CVE package (ATL-117). These are postures
the pack already flags on their own; here they weight a collision rather than
standing alone.

## Research

- **SAFE-MCP SAF-T1301** (Cross-Server Tool Shadowing), **SAF-T1003** (server
  impersonation / rug-pull).
- **OWASP Top 10 for Agentic Applications 2026 - ASI04** (supply chain).
