# Guardrails gap fixture (railed dialog, un-railed execution)

An agent with a real NeMo Guardrails config - input flows, a Colang file, a
declared model - next to an `mcp.json` granting an auto-approved shell server.
The rails govern the conversation channel; the shell tool executes entirely
outside it. **The safety layer is real and it still does not cover the agent's
most dangerous capability.**

```bash
attestral scan examples/guardrails-gap
```

```
3 components · 4 findings · 2 critical · 1 high · 1 medium
```

## What fires, and why

| Rule | Severity | Where | Risk |
|---|---|---|---|
| ATL-103 | critical | `shell` | A shell-capable MCP server is configured at all. |
| ATL-108 | critical | `shell` | Its tool calls are blanket auto-approved: no human checkpoint. |
| **ATL-212** | high | `shell` | **The contradiction.** The rails config and the tool config are two files that cannot see each other: one rails the dialog, the other grants un-railed execution. Only a system model holding both surfaces can say "your safety layer does not extend to your tools." |
| ATL-124 | medium | `guardrails` | The rails themselves are asymmetric: input flows are declared, output flows are not, so a manipulated reply leaves un-railed. |

ATL-103 and ATL-108 are visible to any per-file scanner. ATL-124 needs the
rails config parsed as an artifact. **ATL-212 needs both at once** - that is
the argument for reviewing the design rather than filtering the traffic.

## The right fix

Require human approval on execution tools (remove the blanket auto-approve), or
enforce tool-level policy where the tools run. Then make the rails symmetric:
add `rails.output.flows` (for example `self check output`) so replies are
validated on the way out, not only prompts on the way in.
