# Attack-path synthesis fixture (ATL-210)

The individual rules flag *rungs* — a public endpoint here, a shell tool there,
an egress channel over there. **ATL-210 traces the whole ladder**: a single
connected path where an outside agent gets IN, RUNs code, and gets data OUT.
That assembled kill chain is the strongest thing a system model can produce and
the thing no per-component scanner can.

```bash
attestral scan examples/attack-path
```

## The chain

```
external agent  ──►  partner-ops        (public A2A endpoint, no auth)      ENTRY
                     └─►  ops-shell      (bash -c … → shell)                 PIVOT (code execution)
                          └─►  web       (mcp-server-fetch → network)        IMPACT (exfiltration)
```

One partner agent that reaches the card can delegate a task, have `ops-shell`
run an arbitrary command, and have `web` carry the results out. `ATL-210`'s
finding names every rung:

> Complete external attack path - external agent via public A2A endpoint
> [partner-ops] → code execution [ops-shell] → exfiltration [web].

## What fires, and why

| Rule | Severity | The rung it flags |
|---|---|---|
| **ATL-210** | critical | **The whole chain, assembled.** |
| ATL-208 | critical | Entry → sensitive tool reachability (public endpoint fronts shell). |
| ATL-103 | critical | The shell server itself. |
| ATL-203 | high | The shell + network pair (2-way). |
| ATL-207 | high | The untrusted-input → shell taint pair (2-way). |
| ATL-121 | high | The endpoint declares no auth. |
| ATL-107 | medium | The outbound web channel. |

ATL-208/203/207 each see *two* of the three rungs. Only ATL-210 requires and
names all three — entry **and** pivot **and** impact — so it fires only on a
genuinely complete path, and never on a partial one (remove any one server and
it goes silent; the 2-way rules do not).

## Grounding

- **OWASP Top 10 for Agentic Applications 2026** — ASI08 Cascading Agent
  Failures (the multi-stage chain), ASI07 Insecure Inter-Agent Communication
  (the external entry), ASI05 Unexpected Code Execution (the pivot).
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **MITRE ATLAS AML.T0051** (LLM Prompt Injection) — the trigger that walks the
  chain. <https://atlas.mitre.org/techniques/AML.T0051>

The pivot rung can also come from a **subagent** tool grant (`tools: Bash`), not
just an MCP server — the synthesizer reasons over the whole runtime, servers and
delegates alike (see `tests/test_attack_paths.py`).
