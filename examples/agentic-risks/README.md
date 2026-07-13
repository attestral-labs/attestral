# Agentic-risk fixture

A deliberately risky MCP client configuration. Every server here is realistic on
its own; the point of the fixture is that several of the worst findings only
exist at the *fleet* level - no single server is the bug.

```bash
attestral scan examples/agentic-risks
```

## What fires, and why

| Server | Rules | Risk |
|---|---|---|
| `ops` | ATL-103, ATL-108 | Shell server with an `autoApprove` list: one injected instruction executes with no human checkpoint. |
| `metrics` | ATL-101, ATL-109 | Remote MCP endpoint over plaintext HTTP with no credential - anyone on the path can drive or impersonate the tool server. |
| `deploy` | ATL-110, ATL-104, ATL-112 | API key in argv (visible to every process), and raw AWS credentials in env - a live, provable path from the agent runtime into the cloud boundary, recorded as a reachability edge in the model. |
| `sandbox` | ATL-111 | Docker "sandbox" that bind-mounts `/Users` into the container - the isolation is decorative. |
| `web` | ATL-107 | Fetch tool: an outbound channel that is both an SSRF surface and an exfiltration path. |
| *(fleet)* | **ATL-202** | Lethal trifecta: `notes` reads private data, `web` reaches the internet. An indirect prompt injection in anything the agent reads can quietly exfiltrate the notes. |
| *(fleet)* | **ATL-203** | `ops` executes commands and `web` reaches the internet: download-and-run / C2 from a single injected instruction. |

ATL-202/203 are the findings a per-resource linter structurally cannot produce:
they come from Attestral's system model (which servers exist, what each can
reach, combined), not from any one config block.

## Research these checks are grounded in

- **OWASP Top 10 for Agentic Applications 2026** (ASI01-ASI10), the first
  peer-reviewed taxonomy for agentic risk - notably ASI02 Tool Misuse,
  ASI03 Identity & Privilege Abuse, ASI04 Agentic Supply Chain, ASI05
  Unexpected Code Execution. <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **The lethal trifecta** (private data + untrusted content + external
  communication), Simon Willison, 2025. ATL-202 is this pattern, detected
  statically. <https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/>
- **MCP Security Best Practices**, spec revision 2025-06-18 (confused-deputy,
  token passthrough, session hijacking). ATL-109 checks its core demand:
  authenticate remote servers. <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>
- **Tool poisoning attacks** (malicious instructions in tool metadata),
  Invariant Labs 2025; MDPI/arXiv STRIDE threat model of MCP finding tool
  poisoning the most impactful client-side vulnerability class.
  <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
  - Note: language-based poisoning is deliberately *not* a YAML rule - the risk
    lives in the words, so it is scored by the ML layer (`--ml`), which flags
    the injection payload if you add tool descriptions to this fixture.
- **Cloud Security Alliance, Agentic MCP Security Best Practices v1** (2026) -
  auto-approval, credential handling, and container-scoping guidance mirrored
  by ATL-108/110/111. <https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/>
- **MITRE ATLAS** AML.T0051 (LLM Prompt Injection) for the trifecta chain.
  <https://atlas.mitre.org/techniques/AML.T0051>
