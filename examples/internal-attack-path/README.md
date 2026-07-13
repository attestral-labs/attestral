# Internal attack-path fixture

The external kill chain (ATL-210) needs an A2A endpoint for an outsider to enter
through. Most agent setups have no A2A endpoint at all, and are still fully
exposed: the entry point is a prompt injection carried in content the agent
reads. This fixture has no A2A card, just two tools.

```bash
attestral scan examples/internal-attack-path
```

## The chain

```
untrusted web content  ─►  web    (mcp-server-fetch → network)     ENTRY
                           └─►  ops  (bash -c … → shell)           PIVOT (code execution)
                                └─►  web  (network)                 IMPACT (exfiltration)
```

A page the agent fetches carries an injected instruction, the shell tool runs
whatever it says, and the same fetch tool carries the result back out. Attestral
renders the assembled path at the top of the scan:

```
Attack paths (1)
  internal chain:
    entry: untrusted input ingested by a tool  [web]
    pivot: code execution  [ops]
    impact: exfiltration  [web]
```

## Why this is a rendered path, not a new finding

The internal chain is already covered by two findings, so a third would be
noise:

| The chain's risk | The finding that gates it |
|---|---|
| Untrusted input can reach a code-execution tool | ATL-207 (toxic flow) |
| Shell and outbound network in one fleet | ATL-203 |
| The shell server itself | ATL-103 |
| The outbound channel | ATL-107 |

The value the path adds is the *connection*: it names the entry, the pivot, and
the impact as one story a reviewer can act on, rather than three findings they
have to assemble by hand. The external chain (ATL-210) is a finding because
nothing else represents it; the internal chain is not, because ATL-207 and
ATL-203 already do.

## Grounding

- **OWASP Top 10 for Agentic Applications 2026**, ASI08 Cascading Agent Failures
  (the multi-stage chain) and ASI05 Unexpected Code Execution (the pivot).
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **MITRE ATLAS AML.T0051** (LLM Prompt Injection), the trigger that walks the
  chain. <https://atlas.mitre.org/techniques/AML.T0051>
