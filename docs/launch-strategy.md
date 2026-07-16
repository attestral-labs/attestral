# Launch strategy (grounded)

The ready-to-post channel drafts live in [`../LAUNCH.md`](../LAUNCH.md). This doc
is the layer above them: the positioning, the real-world impact grounding, the
adoption paths, the sequence, and the one decision that needs a human. The
organizing metric is **conviction**: does a skeptical security engineer install
it, keep it past the first run, and tell someone.

> **Update the drafts first.** `LAUNCH.md` predates the flagship. Every draft
> should now lead with **cross-repo toxic flow** (`attestral fleet`, the thing
> incumbents cannot answer) and mention the compile-the-fix / continuous-drift
> loop and the honest limitations page. Those are the strongest converters and
> are currently absent from the drafts.

## Why it matters, grounded

Each capability maps to a concrete cost it removes. This is the framing for every
post, README section, and talk. Ground every claim in the cost avoided, not the
feature.

| Capability | The real-world problem | The impact |
|---|---|---|
| **Agentic depth** (MCP, injection, tool poisoning, excessive agency) | An agent with a shell, a browser, a database, and a Slack token is one injected sentence from walking secrets out. 2025-2026 saw real MCP CVEs and tool-poisoning rug-pulls. | Catch it at design time as a one-line config change, instead of after production as an incident, a re-certification, and a write-up. |
| **System model + toxic flows** | The risk lives in the *integration*. Each server is defensible alone; the lethal trifecta only exists once they run together. Per-config scanners never see it. | Surface the attack path and the trifecta that span servers, the finding a single-file scanner structurally cannot produce. |
| **Cross-repo fleet** (`attestral fleet`, ATL-213) | Real estates span repos: a data reader here, an ops runner there. Each repo passes its own review; the chain completes across the boundary. | Find the cross-repo toxic flow no per-repo tool can see. The flagship differentiator; lead with it. |
| **Config or code** (`code_agent` ingestion) | Most agents are Python (LangGraph, CrewAI, the OpenAI Agents SDK), not `.mcp.json`. A config-only scanner sees a minority of deployments. | The same review runs on the code, so the shell-plus-egress flow is caught whether it is config or three `@tool` functions. |
| **Reachability-based severity** | Alert fatigue gets tools muted and uninstalled. A HIGH with no justification is argued with. | A HIGH ships with the entry-to-exit path that justifies it, so triage trusts it and the tool stays installed. |
| **Baseline + PR action** | A brownfield repo's first scan surfaces hundreds of findings and gets uninstalled. | `--baseline` gates CI on net-new only, so a team adopts on a large existing codebase without a wall of day-one debt. |
| **Remediate + fix** | Findings without fixes get ignored no matter how correct they are. | `remediate` gives the concrete source edit, `fix` compiles the enforceable runtime control. Both ends of "so what do I do." |
| **Evidence chain + accept-risk** | "A security review you can't prove happened is an opinion." Banks and compliance teams need an artifact. | A tamper-evident chain you verify offline, with accept-risk decisions recorded on it. Audit-ready, not a PDF. |
| **Attest -> compile -> drift** | Scanners stop at findings; gateways enforce policies nobody reviewed. | The review compiles into a default-deny runtime policy and a continuous drift sidecar. The review *is* the control. |
| **Honest limitations** | Security people distrust overclaiming. | A plain "what it does not do" page, including where our own detection breaks. Trust is the real distribution. |

## Adoption paths (make the first run trivial)

Ranked by friction. Every launch surface leads with the lowest-friction path that
fits the reader.

1. **Zero install, one command** (the drive-by evaluator who decides in 90
   seconds): `uvx attestral scan .` or `pipx run attestral scan .`, no venv, no
   setup. Also `pip install attestral && attestral scan --local` to review the
   MCP servers already installed on their machine.
2. **CI in a few lines** (the team lead on a Friday):
   ```yaml
   - uses: attestral-labs/attestral@v1
     with: { fail-on: high, baseline: attestral-baseline.json }
   ```
   SARIF into the Security tab, a job summary with the reachable path, and a gate
   on net-new findings, all from one step (see `action.yml`).
3. **`attestral init`** scaffolds the workflow, the pre-commit config, and a
   waivers file in one command.

## Sequence

Launch in waves; do not spend a big channel's one-time attention before the
gallery is ready, because the gallery is the strongest converter.

- **Wave 0, foundation:** current PyPI release, fresh demo GIF, deployed site,
  `SECURITY.md` + `docs/limitations.md`, a signed reproducible release and pinned
  tag, good-first-issues and a DCO note.
- **Wave 1, the depth-rewarding technical audience:** Show HN led by the
  cross-repo demo and the limitations page; r/netsec, r/LocalLLaMA, the MCP and
  agent-framework communities; the launch blog post (the table above, expanded).
- **Wave 2, the real-systems gallery:** the named, responsibly-disclosed findings
  in recognizable projects. One genuine lethal-trifecta screenshot converts more
  than any benchmark. This is the second, bigger push.
- **Wave 3, standards and enterprise:** OWASP Agentic/LLM and MITRE ATLAS
  communities; the evidence chain + AI-BOM as the procurement hook.

## The one decision that needs you: the gallery

The named real-systems gallery is the highest-leverage asset and the only item
that needs a human call on timing. Proposed sequence:
1. Re-run the sweep against a fresh, pinned set of ~15-20 popular public MCP /
   agent projects (`research/mcp-ecosystem` is the seed).
2. Privately disclose each real finding to the maintainer with the exact config
   and the one-line fix, on a standard window (e.g. 90 days) before any named
   publication.
3. Publish the **aggregate** now (already done, no embargo); publish the **named**
   gallery only after the window.

**Decision needed:** approve the target list and the disclosure window, and
whether to notify maintainers now or after Wave 1.

## Measure conviction, not vanity

Time-to-first-value (install-to-first-scan drop-off), retention (does the CI check
stay green or get removed, the loudest signal), and false-positive reports (the
number that decides adoption). Stars and mentions are downstream of these.
