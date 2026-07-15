# External-agent → cloud reachability fixture (ASI07 → ASI03)

A partner-facing agent (`ops-copilot`) exposed over A2A, with one tool behind
it that holds AWS credentials. The danger is a **three-hop path** that no
single check can see: an *external* agent reaches the public A2A card, delegates
a task, that task drives the cloud-credentialed tool, and now a partner agent is
operating inside your cloud account.

```bash
attestral scan examples/a2a-cloud-reach
```

## What fires, and why

| Rule | Severity | Where | Risk |
|---|---|---|---|
| **ATL-209** | critical | *(fleet)* | **The path.** The `ops-copilot` A2A endpoint is *effectively public* (defines a bearer scheme but requires none) and shares a runtime with `aws-tools`, which holds `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. `caller → endpoint → tool → cloud`. |
| ATL-112 | high | `aws-tools` | The tool server holds raw cloud credentials (the middle hop, seen on its own). |
| ATL-123 | high | `ops-copilot` | The card defines an auth scheme but requires none - a public agent that looks protected. |
| ATL-104 | medium | `aws-tools` | The AWS secret is passed in `env`. |

ATL-112, ATL-123, and ATL-104 are each real and each visible to a per-component
scanner. **ATL-209 is the one that isn't** - it exists only because the A2A
endpoint and the cloud-credentialed server are modeled in the same graph. That
is the whole argument for a system model.

## Why this is the right fix, not just the right flag

The A2A / RFC 8693 delegation guidance is explicit: when an agent delegates to a
downstream capability, it should **exchange** the caller's identity for a
narrowly-scoped, short-lived token for that specific action - never co-locate a
broad standing credential with an externally-reachable agent. ATL-209 fires on
exactly the anti-pattern that guidance exists to prevent.

## Research these checks are grounded in

- **OWASP Top 10 for Agentic Applications 2026** - ASI07 Insecure Inter-Agent
  Communication and ASI03 Identity & Privilege Abuse (an external identity
  reaching a standing cloud credential).
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **OAuth 2.0 Token Exchange (RFC 8693)** - the scoped-token-exchange pattern
  for agent delegation; ATL-209 flags its absence across the A2A boundary.
  <https://datatracker.ietf.org/doc/html/rfc8693>
- **MCP Security Best Practices (2025-06-18)** - the "Token Passthrough"
  anti-pattern: a broker must not forward a broad credential it was not scoped
  to use. <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>
- **A2A Protocol AgentCard v1** - `securitySchemes` vs `security`; an absent or
  empty `security` requirement is a public agent. <https://a2a-protocol.org/>
- **NIST SP 800-53 AC-4** (Information Flow Enforcement): ATL-209 is an
  external-caller → internal-cloud information-flow crossing.
