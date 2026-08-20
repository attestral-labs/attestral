# LangGraph cross-node toxic flow

`3 components · 4 findings · 4 high`

A LangGraph `StateGraph` whose lethal trifecta is **split across three nodes**, so
no single node holds the whole thing - and none of the nodes is a `@tool`, so a
tool-only scanner would not model this file at all:

- **intake** ingests untrusted external content (`requests.get` → network).
- **executor** runs commands (`subprocess.run(..., shell=True)` → shell / code execution).
- **notifier** posts to an outbound channel (`requests.post` to a Slack webhook → egress).

Attestral models each `add_node("name", fn)` in the graph as its **own**
`code_agent` component with only that node's capabilities, read from the node
function's body, and adds `invokes` edges from `add_edge` / `add_conditional_edges`
(`intake → executor → notifier`, with the `START`/`END` boundaries dropped). The
fleet path synthesis then assembles the cross-node attack path — entry (intake) →
pivot (executor) → impact (notifier) — that a per-file scanner, seeing one blob,
would report without the structure. The pivot sits on a *different* node than the
entry and the sink: a flow that only a system model reveals.

```sh
attestral scan examples/langgraph-crossagent
```
