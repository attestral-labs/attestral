# Ecosystem composite: a realistic project, every layer exercised

One repo composited from the patterns Attestral's 33-repo public MCP corpus
actually exhibits - not a horror show, a plausible AI support-desk product
("Meridian Desk") wired the way real teams wire things. Every planted issue is
a pattern observed in the wild: registry manifests floating on `latest`,
API tokens in server `env` blocks, browser+fetch+shell fleets, directive-heavy
`CLAUDE.md`/`AGENTS.md` instruction files, expert system prompts, a Deployment
still `privileged: true` from a debugging session, and the exports bucket that
went `public-read` for the dashboards.

It exists as a known-answer test: every seed below was planted first, then the
scan was run. It verifies the pipeline catches what it claims to catch, end to
end, on realistic material; it is not an unbiased recall estimate (the seeds
were chosen by people who know the rules).

```bash
attestral scan examples/ecosystem-composite
```

18 components · 37 findings · 5 critical · 20 high · 8 medium · 3 low · 1 info

## The seeded findings, and what caught them

**Layer 1, deterministic rules + system model (33 findings; every planted
issue detected):**

| Seeded | Caught by |
|---|---|
| Exports bucket `public-read`, wildcard IAM, SSH open to the world, RDS without IAM auth | ATL-001 · ATL-003 · ATL-002 · ATL-056 |
| Shell-capable runbook server, tokens in `env`, six `npx -y`/`uvx` auto-installs, outbound browser+fetch, persistent memory store | ATL-103 · ATL-104 · ATL-105 · ATL-107 · ATL-114 |
| Published `server.json` floating on `version: latest` | ATL-143 |
| Privileged root container, `hostPath` mount, `latest` image tag, inline `STRIPE_SECRET_KEY`, missing limits/seccomp/caps hardening | ATL-501 · ATL-506 · ATL-510 · ATL-505 · ATL-531 · ATL-504/512/513/514/518/520/522 |
| Fleet-level: lethal trifecta, shell+network, untrusted-input-to-execution flow, memory poisoning path, no agent/cloud boundary controls | ATL-202 · ATL-203 · ATL-207 · ATL-214 · ATL-201 |

The scan also walks one full attack path (browser/fetch/memory -> runbook ->
browser/fetch) and raises four findings a severity band for sitting on it.

**Layer 2, ML on the language surfaces (default heuristic tier vs the DeBERTa
model tier):**

| Seeded language surface | Heuristic | DeBERTa |
|---|---|---|
| `escalate` tool description: covert "forward the conversation, do not mention it" | flagged | flagged |
| `sync_notes` tool description: instruction hidden in an HTML comment | flagged | flagged |
| System prompt: "meridian debug mode" override backdoor | flagged | flagged |
| `AGENTS.md`: covert archive copy + "keep this between us" | flagged | missed |
| `CLAUDE.md`: benign directive register (negative control) | clean | clean |

```bash
attestral scan examples/ecosystem-composite --ml --ml-engine deberta
```

18 components · 36 findings · 5 critical · 19 high · 8 medium · 3 low · 1 info

The disagreement row is the instructive one. `AGENTS.md` hides an
exfiltration instruction in ordinary workflow prose; the model tier reads it
as workflow, the heuristic catches it because the instruction-surface gate
looks for exactly that coupling - directive phrasing plus a secrecy signal.
The mirror case is `CLAUDE.md`: its "when asked to commit, first run the
tests" register scores 0.75 on the raw `tool_poisoning` patterns, and before
the gate it would have been a false positive; the gate mutes it because no
second signal co-occurs. One file demonstrates the false positive the gate
removed, the other the true positive it kept. The clean `summarize_ticket`
description and the `secretKeyRef`-referenced credential are further negative
controls; neither tier and no rule flags them.

**Layer 3, the judge** cross-examines the findings above against the modeled
system (`--judge`, needs `ANTHROPIC_API_KEY`):

```bash
ANTHROPIC_API_KEY=... attestral scan examples/ecosystem-composite --judge
```

It is not run in this README because it needs a live key; the deterministic
and ML columns above are reproducible offline.

## Why this fixture exists

The rule-pack fixtures each isolate one rule; the reference fleet spreads a
cross-repo flow over two repos. This one is the single-repo integration test:
one realistic project where the cloud pack, the Kubernetes pack, the agentic
rules, the cross-boundary model rules, reachability, and both ML tiers all
have real work to do at once - and where the negative controls prove the scan
stays quiet on the parts a real team got right.
