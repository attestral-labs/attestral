# OpenAI Agents SDK handoff toxic flow

`4 components · 4 findings · 4 high`

An OpenAI Agents SDK network whose lethal trifecta is **split across handoff
targets**, so no single agent holds the whole thing:

- **Triage** routes the request and hands off to **Fetcher** (a pure router, no tools of its own).
- **Fetcher** ingests untrusted external content (`fetch_url` → network) and hands off to **Operator**.
- **Operator** runs commands (`run_command` → shell / code execution) and hands off to **Mailer**.
- **Mailer** posts the result outbound (`send_email` → messaging / egress).

Attestral models each `Agent(name=..., tools=[...], handoffs=[...])` as its **own**
`code_agent` component with only that agent's capabilities, and turns every
`handoffs=[...]` entry into an `invokes` delegation edge (`Triage → Fetcher →
Operator → Mailer`). The fleet path synthesis then assembles the cross-agent
attack path — entry (Fetcher) → pivot (Operator) → impact (Mailer) — that a
per-file scanner, seeing one blob, would report without the structure. The pivot
sits on a *different* agent than the entry and the sink: a flow only a system
model reveals.

```sh
attestral scan examples/openai-agents-handoff
```
