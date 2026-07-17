# agent-fleet-flows

Four MCP servers that are unremarkable one at a time, but whose *combination*
forms three architecture-level flows only the system model can see. No single
server is the finding; the crossing is.

Scan it:

```bash
attestral scan examples/agent-fleet-flows
```

| Flow | Rule | The crossing |
|---|---|---|
| Memory poisoning | ATL-214 | `web` ingests untrusted external content and `memory` is a persistent vector store, so attacker-controlled text can be written into long-term memory and steer the agent on future, unrelated sessions. |
| Covert tool invocation | ATL-215 | `assistant` declares the MCP `sampling` capability and is auto-approved, so a server-initiated model completion can drive tools with no human checkpoint (Unit 42, MCP sampling attack vectors, 2025). |
| Injection reaches cloud | ATL-216 | `web` ingests untrusted content and `cloud` holds AWS credentials in one agent, so an indirect prompt injection can drive cloud APIs with those keys - agent-to-cloud reachability with no public endpoint required. |

Each server also trips its own per-component checks; the point of the fixture
is the fleet-level flows layered on top of them:

| Rule | Component-level finding |
|---|---|
| ATL-104 | `cloud` receives a secret (`AWS_SECRET_ACCESS_KEY`) via `env`. |
| ATL-107 | `web` (mcp-server-fetch) is an outbound network / browser channel. |
| ATL-108 | `assistant` auto-approves every tool call (`"autoApprove": ["*"]`). |
| ATL-112 | `cloud` holds live cloud credentials. |
| ATL-114 | `memory` (mem0) is a persistent memory / vector store. |
| ATL-125 | `assistant` declares the MCP `sampling` capability. |
| ATL-202 | Fleet-level lethal trifecta: private data (`cloud` creds) + untrusted input (`web`) + an exit (`web` outbound). |
