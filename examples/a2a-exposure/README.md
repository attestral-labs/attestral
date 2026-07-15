# A2A external-exposure fixture (ASI07)

An agent published to *other* agents over the A2A protocol, with one tool
behind it. Neither file is alarming alone - the danger is that an **external,
unauthenticated caller can reach an internal tool through the agent**, which
only appears when you model the agent card and the tool fleet as one system.

```bash
attestral scan examples/a2a-exposure
```

## What fires, and why

| Rule | Severity | Where | Risk |
|---|---|---|---|
| **ATL-208** | critical | *(fleet)* | The `support-concierge` A2A endpoint is *effectively public*, and behind it sits `customer-db` (a Postgres MCP server → `database` capability). Any partner agent that reaches the card URL can delegate a task that reads the customer database. The inter-agent analogue of the lethal trifecta - visible only when the endpoint and the fleet are modeled together. |
| ATL-123 | high | `support-concierge` | The card **declares** a `partnerBearer` scheme but has **no `security` requirement**, so per the A2A spec every skill is callable with no credential. Auth "is configured" - and enforces nothing. This is the misread a reviewer skims past. |

Note what does *not* fire: **ATL-121** (declares no auth at all) stays silent
because schemes *are* declared - ATL-123 is the more precise finding for the
"defined but not required" case. **ATL-122** stays silent because the endpoint
is HTTPS. The tool itself is clean (pinned version, no secrets in env). The
only findings are the two that require reasoning about the *relationship*
between the endpoint and the fleet.

## The precision that matters

`securitySchemes` (auth **defined**) and `security` (auth **required**) are
different fields in the A2A AgentCard. A card can define bearer auth and still
require none - a public agent that looks protected. Attestral derives
`_auth_defined_not_required` in the ingester so the rule stays a simple typed
check, and `_effectively_public = _no_auth_declared or _auth_defined_not_required`
is what the cross-boundary reachability rule (ATL-208) keys on.

## Research these checks are grounded in

- **OWASP Top 10 for Agentic Applications 2026** - ASI07 Insecure Inter-Agent
  Communication (ATL-123, ATL-208) and ASI03 Identity & Privilege Abuse
  (ATL-208: an external identity reaching internal privilege).
  <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **A2A Protocol AgentCard v1** - `securitySchemes` (OpenAPI-style) declares
  auth methods; a non-empty `security` list declares which are required. Absent
  or empty `security` = a public agent. <https://a2a-protocol.org/>
- **NIST SP 800-53 AC-4** (Information Flow Enforcement): ATL-208 is an
  information-flow crossing - external caller → internal sensitive tool.
