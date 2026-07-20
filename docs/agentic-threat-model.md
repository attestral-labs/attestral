# Attestral's agentic coverage, mapped to the agent-security SoK

This maps Attestral's agentic checks onto the taxonomy in **Kim, Liu, Wang, Qiu,
Li, Guo, Song - _The Attack and Defense Landscape of Agentic AI: A Comprehensive
Survey_ (arXiv:2603.11088, 2026)**, the first systematic SoK of AI-agent
security. The survey organizes the field into six attack vectors (V1-V6), seven
security risks (R1-R7), and seven design dimensions. Attestral is a *static
design reviewer*, so it covers the parts of that landscape visible before the
agent runs: configuration, tool surface, credentials, standing memory, and the
combinations across them. Where a risk lives in language (injection text) it is
scored by the ML layer; where it only appears at runtime it is caught by the
`compile` → `drift` loop.

Framework refs in `core_rules.yaml` cite these as `Agentic-SoK 2026 <code>`.

## Attack vectors (V1-V6)

| Vector | Attestral coverage |
|---|---|
| **V1 Indirect prompt injection** | ML layer scores tool/description/instruction text (`--ml`); ATL-107 flags the outbound channel that makes injection exfiltratable; the injection-reachability pass raises an ML injection finding to critical only when its surface can reach a secret, egress, cloud, or code execution, and leaves an injectable dead-end at its ML severity (`attestral/injection_reach.py`) |
| **V2 Malicious data injection** (typosquat / package) | ATL-105 (auto-install `npx -y`/`uvx`), ATL-106 (mutable `@latest` tag), ATL-117 (known-CVE package version, e.g. mcp-remote CVE-2025-6514), ATL-219 (confusable / homoglyph tool name that impersonates a trusted tool without an exact clash), ATL-152 (committed settings that auto-trusts a plugin marketplace - a plugin silently bundles hooks, MCP servers, and subagents, so opening the repo inherits that supply chain), ATL-153 (pre-release / rolling channel `@beta`/`@rc`/`@next`, the rug-pull sibling of `@latest`), ATL-154 (a remote-debugging / inspector port left in a committed launch command), ATL-155 (a `curl \| sh` fetch-and-execute one-liner baked into a standing instruction or skill file) |
| **V3 Tool poisoning & manipulation** | ML layer on tool descriptions; ATL-204/205/206 cross-server tool shadowing, ATL-219 confusable-name shadowing (a look-alike an exact match misses), trust-asymmetry escalation (a collision is raised when a lower-trust mutable package can shadow a trusted tool, `attestral/trust_asymmetry.py`); ATL-150 external `$ref` in a tool input schema (schema poisoning / SSRF, MCP spec SEP-2106); DRF-005 rug-pull (manifest or schema changed since attestation) |
| **V4 Direct prompt injection** | Out of static scope (runtime user input) - noted for completeness |
| **V5 Model poisoning** | Out of static scope (model internals) |
| **V6 Memory poisoning** | **ATL-113** (world-writable instruction file), **ATL-114** (persistent memory store is the poisoning target), **ATL-118** (command-running hooks in `.claude/settings.json`, CVE-2025-59536) |

## Security risks (R1-R7)

| Risk | Attestral coverage |
|---|---|
| **R1 Heterogeneous untrusted interfaces** | ATL-107 (network/browser reach), ATL-102 (broad filesystem), the whole `scan --local` tool-surface inventory |
| **R2 Wrong instruction following** | ML layer on instructions + descriptions (injection that overrides intent) |
| **R3 Unconstrained / unsafe data flow** | **ATL-202 lethal trifecta** (private data + egress), **ATL-207 toxic flow** (untrusted input → code execution, with named source/sink servers and taint edges in the model) |
| **R4 Hallucination & model mistakes** (package hallucination) | ATL-105/106 supply-chain pinning |
| **R5 Private data leakage** | ATL-202, ATL-112 (agent→cloud credential reachability edge), ATL-104/110 (credential exposure), ATL-149 (a vector/memory store shared across users by one static credential - cross-tenant embedding leakage, OWASP LLM08; distinct from the public-endpoint shared-identity case in that it needs no exposed endpoint), ATL-151 (a secret hard-coded in an agent-instruction file - OWASP LLM07 System Prompt Leakage - which version control, logs, and every run then leak) |
| **R6 Unintended / unauthorized action & data corruption** | ATL-108 (auto-approved actions), ATL-103 (shell), ATL-203 (shell+network), ATL-114 (poisoned memory corrupts later behavior) |
| **R7 Resource drain / DoS** | **DRF-006/007** - the compiled policy carries tunable `budgets`, and `drift` flags runaway tool-call loops and per-server volume overruns against runtime telemetry |

## Design dimensions → the signals Attestral reads

The survey's thesis is that *flexibility along each dimension expands the attack
surface*. Attestral makes several of these dimensions measurable from config:

- **Tool** - capability classes per server (filesystem, network, messaging,
  database, saas_data, memory, shell) in the MCP ingester; the fleet combination
  is what ATL-202/203 reason over.
- **Memory** - persistent stores detected as the `memory` capability (ATL-114).
- **Access sensitivity** - cloud credentials in a tool server (ATL-112) and the
  private-data capability classes feeding the trifecta.
- **Action** - shell/execution capability (ATL-103) vs. read-only; auto-approval
  removes the human checkpoint on actions (ATL-108).
- **Input trust** - an outbound/browser tool ingests arbitrary external content
  (ATL-107), the classic indirect-injection entry point.

## What the survey highlights that Attestral does *not* yet cover

Tracked as future work, honest about the gaps:

- **Full value-level taint tracking** (survey §5.2.3) - ATL-207 now records
  source→sink *paths* structurally (taint edges) and the trifecta flags the
  capability, but Attestral still does not trace a specific tainted *value*
  through the agent end to end (that needs runtime instrumentation).
- **Identity & delegation** (survey §5.4) - partial (ATL-109 remote auth,
  ATL-112 cloud-credential reachability); confused-deputy / token-passthrough
  and agent-to-agent delegation identity are next.
- **A2A surfaces** - competitors (Cisco AI Defense) scan agent-to-agent
  protocols; Attestral now ingests agent skills (SKILL.md, ATL-116) but does not
  yet model A2A / multi-agent delegation graphs.

Closed since the survey mapping was written: **R3 unsafe data flow** (ATL-207)
and **R7 resource/DoS** (DRF-006/007). The **V3 tool-shadowing** wave has since
been extended with confusable-name collisions (ATL-219) and trust-asymmetry
severity, and **V1 injection** coverage now escalates by reachability, so an
injectable surface is rated by what it can actually reach rather than by the
presence of injection text alone.

_Source: Kim et al., arXiv:2603.11088, 2026. Citations in this repo point to the
survey's own R/V notation for traceability; they are an audit aid, not a claim
of endorsement._
