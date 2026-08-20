# AutoGen group-chat cross-agent toxic flow

`3 components · 4 findings · 4 high`

An AutoGen `RoundRobinGroupChat` whose lethal trifecta is **split across three
agents**, so no single agent holds the whole thing - and the tools are plain
callables handed to each agent's `tools=[...]`, not `@tool` decorators, so a
tool-only scanner would not model this file:

- **Researcher** ingests untrusted external content (`fetch_page` → network).
- **Operator** runs commands (`run_shell` → shell / code execution).
- **Reporter** posts to an outbound channel (`post_slack` → messaging / egress).

Attestral models each `AssistantAgent(name=..., tools=[...])` in the team as its
**own** `code_agent` component with only that agent's capabilities, and chains the
team's members with `invokes` edges in round-robin order (`Researcher → Operator →
Reporter`). The fleet path synthesis then assembles the cross-agent attack path —
entry (Researcher) → pivot (Operator) → impact (Reporter) — that a per-file
scanner, seeing one blob, would report without the structure. The pivot sits on a
*different* agent than the entry and the sink: a flow only a system model reveals.

```sh
attestral scan examples/autogen-groupchat
```
