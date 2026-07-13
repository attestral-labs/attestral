# Multi-agent delegation fixture

The MCP fleet here is a single, pinned, narrowly scoped filesystem server -
safe on its own. What flips the system into two critical capability chains is
**delegation**: a subagent definition whose tool grants (`Bash`, `WebFetch`)
exist entirely outside the MCP server list, plus an A2A agent card exposing
this workspace to other agents. Capabilities compose transitively; a scanner
that only reads `mcpServers` blocks calls this repo clean.

```bash
attestral scan examples/multi-agent
```

## What fires, and why

| Rule | Severity | Where | Risk |
|---|---|---|---|
| **ATL-202** | critical | *(fleet)* | Lethal trifecta *across the delegation hop*: `notes` reads private data, `deploy-bot` reaches the network. The finding names the chain: `filesystem via notes; network via deploy-bot`. |
| **ATL-203** | high | *(fleet)* | Shell + network - both arrive through one delegate's tool grants, not through any MCP server. |
| **ATL-207** | high | *(fleet)* | Taint path: the same delegate ingests untrusted web content and executes commands. |
| **ATL-208** | critical | *(fleet)* | The `support-triage` A2A endpoint is unauthenticated, so an *external* agent can reach the internal `notes` (filesystem) and `deploy-bot` (shell) tools through it - the inter-agent analogue of the trifecta. |
| **ATL-210** | critical | *(fleet)* | The assembled kill chain: external agent via the `support-triage` A2A endpoint → code execution via `deploy-bot` (shell) → exfiltration via `deploy-bot` (network). One connected path where an outsider gets in, runs code, and gets data out. |
| ATL-119 | high | `deploy-bot` | A delegate holding shell execution: one injected instruction anywhere in the chain becomes command execution. |
| ATL-120 | medium | `helper` | No `tools:` list - the delegate inherits the main agent's entire tool surface (excessive agency). Deliberately contributes **no** capabilities to the fleet rules: unknown grants are flagged, never guessed. |
| ATL-121 | high | `support-triage` | A2A agent card with no `securitySchemes`/`security` - per the A2A spec, that is a public agent anyone can delegate tasks to. |
| ATL-122 | high | `support-triage` | The advertised A2A endpoint is plaintext `http://` - inter-agent task traffic can be read or altered in transit. |

## Research these checks are grounded in

- **OWASP Top 10 for Agentic Applications 2026** - ASI02 Tool Misuse &
  Exploitation, ASI05 Unexpected Code Execution (ATL-119), ASI07 Insecure
  Inter-Agent Communication (ATL-121/122).
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **A2A Protocol specification v1** - the AgentCard is served at
  `/.well-known/agent-card.json`; authentication is declared in
  `securitySchemes` (OpenAPI 3 shape) and required via `security`. A card
  without them describes a public agent. <https://a2a-protocol.org/>
- **OWASP LLM Top 10 2025** - LLM06 Excessive Agency (ATL-120).
- **Claude Code subagents** - delegate definitions in `.claude/agents/*.md`;
  frontmatter `tools:` grants built-ins (Bash, WebFetch, ...) independent of
  any MCP server config; omitting `tools:` inherits everything.
  <https://docs.claude.com/en/docs/claude-code/sub-agents>
- **The lethal trifecta** (Simon Willison, 2025), now detected across the
  delegation graph rather than only within one server fleet.
  <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>
