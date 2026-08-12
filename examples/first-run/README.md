# First run: the 60-second wow

This is a normal `.mcp.json`. It is the kind of config a developer actually has:
the filesystem server, GitHub, a web fetcher, a database. Nothing here looks
wrong on its own. That is the point.

```bash
pip install attestral
attestral scan examples/first-run
```

```
4 components · 8 findings · 1 critical · 5 high · 2 medium

CRITICAL (1)
  ATL-202  Tool fleet forms an exfiltration chain (lethal trifecta)  (model)
```

## What one command just told you

The critical finding is not on any single server. It is on the **combination** -
and it is the thing no per-file linter can see, because it only exists once you
model the whole fleet:

- `postgres` reads your **customer database** (private data).
- `fetch` pulls in **web pages** (untrusted content that can carry an injected
  instruction).
- `github` and `fetch` can send data **out** of the boundary.

Put those three in one agent session and a single poisoned web page can tell the
agent to read your customer table and post it to an attacker. That is the
**lethal trifecta**: private data, untrusted input, and an outbound channel, all
reachable at once. Attestral names it, and `attestral explain ATL-202` walks the
exact source-to-sink flow.

The rest of the findings are the ordinary sharp edges you stopped noticing:

- `filesystem` is rooted at `/Users/dev`, your **home directory**, so the agent
  (and any injection that reaches it) can read `~/.ssh`, `~/.aws/credentials`, and
  every other project. (ATL-102)
- Your **GitHub token** sits in plaintext env where tool output can echo it.
  (ATL-104)
- Every server auto-installs from `npx -y` / `uvx` with no pinned version, so a
  typosquat becomes code execution in your agent. (ATL-105)

## See what your own agents can do

The demo is a fixture. This is the visceral part:

```bash
attestral scan --local        # audits the MCP configs installed on THIS machine
                              # (Claude Desktop, Claude Code, Cursor, VS Code, Windsurf)
attestral posture examples/first-run   # sign WHAT the agent can do, as a verifiable claim
```

`posture` prints the capability envelope in one line - here,
`database, filesystem, network, saas_data` with `lethal trifecta: YES` - and
signs it as an in-toto predicate a cosign or Kyverno gate can verify offline.

Design review, not SAST. Attestral reads the declared surface and reasons over a
single system model. It does not execute your agent or read the inside of a
tool's code. A reachable path is necessary, not proof of exploit. That honesty is
the point: the trifecta above is real, and it was one command away.
