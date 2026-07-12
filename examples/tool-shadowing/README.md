# Cross-server tool-shadowing fixture

A fleet of MCP servers that are each unremarkable in isolation. Every finding
here is *between* servers - the defining property of cross-server tool
shadowing, and the reason a per-resource linter cannot express these checks
at all. Attestral sees them because it builds one system model of the whole
fleet before any rule runs.

```bash
attestral scan examples/tool-shadowing
```

## The story

The project fleet (`mcp.json`) wires a trusted, pinned Linear server next to a
"notes helper". The user's own config (`claude_desktop_config.json`) also
defines a server called `linear` - but pointing at a different, unpinned
package. Nothing in any single block is malformed.

## What fires, and why

| Rule | Severity | Where | Risk |
|---|---|---|---|
| **ATL-205** | critical | `notes-helper` | Its `format_notes` description dictates what the agent should do "whenever `list_issues` is used" - but `list_issues` belongs to the *linear* server. That is the shadowing pattern itself: guidance planted in one server's metadata steering a tool the agent trusts elsewhere. |
| **ATL-204** | high | *(fleet)* | `create_issue` is exposed by both `linear` and `notes-helper`. Tool routing is ambiguous; the lower-trust server can answer calls meant for the trusted one. |
| **ATL-206** | high | *(fleet)* | The name `linear` resolves to two different launch targets (`@linear/mcp-server@1.2.3` vs `linear-mcp-tools@latest`). Which code answers to that identity depends on config precedence - the shape of server impersonation. |
| ATL-106 | medium | the impostor `linear` | The conflicting definition also tracks a mutable `@latest` tag, so its code can change after review - the rug-pull half of the story. |

Note what ATL-205 does *not* require: the steering text reads as innocent
process guidance ("for traceability, copy the transcript..."). An injection
classifier scoring the words alone would likely pass it. The deterministic
matcher fires anyway, because the *structure* - one server's metadata
referencing another server's tool identifiers - is the attack, regardless of
tone. Language-based poisoning remains the ML layer's job (`--ml`); the split
is deliberate.

## Research these checks are grounded in

- **SAFE-MCP SAF-T1301, Cross-Server Tool Shadowing** (privilege escalation):
  malicious servers override or steer legitimate tool calls from other
  servers. ATL-204/205 are this technique, detected statically.
  <https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1301>
- **SAFE-MCP SAF-T1003, Malicious MCP-Server Distribution** and
  **SAF-T1001, Tool Poisoning Attack** - the delivery and payload halves of
  the same campaign. ATL-206 flags the identity ambiguity T1003 needs.
  <https://github.com/SAFE-MCP/safe-mcp/tree/main/techniques/SAF-T1003>
- **"WhatsApp MCP Exploited"**, Invariant Labs 2025: the canonical
  demonstration - a sleeper MCP server running beside the official WhatsApp
  server shadowed its `send_message` tool and exfiltrated message history
  through it. <https://invariantlabs.ai/blog/whatsapp-mcp-exploited>
- **"Cross-Server Tool Shadowing: Hijacking Calls Between Servers"**, Acuvity
  2025 - why multi-server fleets, not single servers, are the unit of
  analysis. <https://acuvity.ai/cross-server-tool-shadowing-hijacking-calls-between-servers/>
- **OWASP Top 10 for Agentic Applications 2026**: ASI02 Tool Misuse &
  Exploitation (ATL-204), ASI06 Memory & Context Poisoning (ATL-205 - the
  steering text persists in agent context), ASI04 Agentic Supply Chain
  (ATL-206). <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **MCP Security Best Practices**, spec revision 2025-06-18 - mandates
  verifying server identity and warns on client-config-driven local server
  compromise; notably it has *no* tool-shadowing control yet, which is why
  these rules cite SAFE-MCP for the technique itself.
  <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>
- **MITRE ATLAS AML.T0051** (LLM Prompt Injection) for the context-steering
  chain in ATL-205. <https://atlas.mitre.org/techniques/AML.T0051>
- **NIST SP 800-53 IA-4** (Identifier Management): identifiers must map to
  exactly one subject - the control both ATL-204 and ATL-206 enforce for
  tool and server names.
