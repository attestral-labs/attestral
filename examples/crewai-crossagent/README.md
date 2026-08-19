# CrewAI cross-agent toxic flow

`3 components · 4 findings · 4 high`

A CrewAI crew whose lethal trifecta is **split across three agents**, so no single
agent holds the whole thing:

- **Web Researcher** ingests untrusted external content (`web_fetch` → network).
- **Shell Operator** runs commands (`run_shell` → shell / code execution).
- **Slack Reporter** posts to an outbound channel (`post_to_slack` → messaging).

Attestral models each `Agent(role=..., tools=[...])` in the crew as its **own**
`code_agent` component with only that agent's capabilities, and adds `invokes`
delegation edges between them. The fleet path synthesis then assembles the
cross-agent attack path — entry (Web Researcher) → pivot (Shell Operator) →
impact (Slack Reporter) — that a per-file scanner, seeing one blob, would report
without the structure. The pivot sits on a *different* agent than the entry and
the sink: this is a flow that only a system model reveals.

```sh
attestral scan examples/crewai-crossagent
```
