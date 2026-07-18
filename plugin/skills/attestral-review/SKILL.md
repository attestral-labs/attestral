---
name: attestral-review
description: Security design review for AI agents, MCP servers, and the cloud they can reach. Use when adding or editing an MCP server, agent config, subagent, system prompt, or tool definition, or when the user asks whether an agent setup is safe or has prompt-injection, tool-poisoning, excessive-agency, or lethal-trifecta risk. Runs `attestral scan` and explains the findings.
---

# Attestral security review

Attestral is a security design-review scanner for agentic systems. It reads the
declared surface (MCP configs, agent wiring, system prompts, tool descriptions,
and Terraform / Kubernetes) and reasons over a single system model to find the
risks that matter for agents: prompt injection, tool poisoning, excessive
agency, and the toxic flows that only exist across tools. A shell tool and an
egress tool are one injected sentence apart, and neither looks dangerous alone.

It is a design review, not a SAST tool. It reads the declared configuration; it
does not read the inside of a tool's implementation or run anything against a
live agent.

## When to use this skill

Reach for it whenever the agent's attack surface changes, or the user asks about
safety:

- A new or edited `.mcp.json` / MCP server, subagent, A2A card, or `@tool` function.
- A new or edited system prompt or agent-instruction file.
- The user asks "is this agent config safe", "could this be prompt-injected",
  "review this before I ship", or names tool poisoning, excessive agency, or a
  lethal trifecta.

## Install (once)

Attestral is a Python CLI with two core dependencies.

```bash
pipx install attestral        # isolated, recommended
# or: pip install attestral
```

The prompt-injection ML tier runs with no extra install (a zero-dependency
heuristic). `pip install "attestral[ml]"` upgrades it to a local DeBERTa
classifier; `[terraform]` adds HCL parsing.

## Core moves

Run these from the repo root and read the grouped, severity-ordered output.

```bash
attestral scan .                      # review this project (auto-discovers configs)
attestral scan . --ml                 # add prompt-injection scoring on language surfaces
attestral scan --local                # audit the MCP servers installed on THIS machine
attestral explain ATL-107             # what one finding means and how to fix it
```

To gate a change so only structural, zero-false-positive findings fail:

```bash
attestral scan . --min-confidence high --fail-on high
```

## Reading the output

- Findings are grouped by severity and tagged by origin: `deterministic` (a
  typed rule), `ml` (prompt-injection scoring), or `llm` (the optional judge).
- A finding on a walked attack chain carries a `path:` line naming
  entry -> pivot -> impact, and its severity is raised one band. That path is
  the story to surface, not just the rule title.
- The headline findings are the cross-tool ones (lethal trifecta, toxic flow):
  they exist because two capabilities co-occur, so look at the flow, not one
  tool.
- `confidence` (high / medium / low) tags how false-positive-prone a finding is.
  Deterministic rules are high; the ML tier tracks its probability.

## Handling a finding

1. Run `attestral explain <ID>` for the concrete fix and the framework citation
   (OWASP Agentic / LLM Top 10, MITRE ATLAS, NIST, CIS).
2. Apply the remediation: narrow a tool's scope, add a human-approval gate,
   allowlist egress, drop a secret from env.
3. If a finding is a deliberate accepted risk, do not silence it silently.
   Either a one-line `// attestral:ignore ATL-xxx reason: ...` marker in the
   config, or `attestral accept <path> <rule> <component> -r "why"` for a
   provenance-pinned waiver. Both keep the finding in the evidence chain.

## Gate it in CI

`attestral init` scaffolds a GitHub Action (SARIF into the Security tab, a
net-new baseline gate, a job summary with the reachable path) and a pre-commit
hook. Suggest it once a project scans clean or its findings are triaged.

Do not overstate results. A reachable path is necessary for exploitation, not
sufficient, and a clean scan means the declared surface looks sound, not that
the implementation is proven safe.
