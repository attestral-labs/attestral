# Real-systems gallery: disclosure execution plan

Status: **approved to proceed** (owner sign-off). The channel drafts, including
the maintainer disclosure email, live in [`../LAUNCH.md`](../LAUNCH.md) section 6.
This doc is the operational plan and the status tracker. The aggregate (33
servers) is already published with no embargo; this covers the **named** gallery.

> **Hard gate: sending a disclosure to a real maintainer is a human action.**
> Every draft here is staged for a person to review and fire. Nothing in this
> repo emails a maintainer automatically, and no named result publishes until
> the disclosure window for that project has elapsed.

## Target selection criteria

Pick 15-20 projects that maximize conversion while being fair to maintainers:
- **Recognizable**: a name a skeptical engineer knows (a popular MCP server, a
  widely-used agent framework example, a vendor's reference server).
- **A real, shipped config**: the finding must be in a config the project
  actually publishes (README `mcpServers` block, a committed example), not a
  contrived one.
- **An act-on-it finding**: prefer the compositional ones (lethal trifecta,
  cross-repo/fleet flow, a reachable attack path) over a lone low-severity nit.
  One genuine trifecta in a known project beats ten small hits.
- **Responsive maintainer**: an active repo with a security contact or a
  SECURITY.md, so the disclosure lands.

Seed set: the `research/mcp-ecosystem` corpus already scanned for the aggregate.
Re-run the sweep at fresh pinned commits before disclosing (configs drift).

## Sequence

1. **Re-run the sweep** (`research/mcp-ecosystem/scan_ecosystem.py`) at pinned
   commits; select the 15-20 targets by the criteria above. Record commit SHAs.
2. **Draft one disclosure per target** from the LAUNCH.md template: the exact
   config lines, the finding id + why it matters, and the one-line fix. Keep it
   short, respectful, and fix-first.
3. **Send** (human action) on a standard window (propose **90 days**) before any
   named publication. Log the send date per target below.
4. **Publish the aggregate** now (done). Publish the **named** gallery per target
   only after its window elapses, with maintainer acknowledgement where given.
5. Ship the harness, the pinned target list, and the per-repo results alongside
   the named write-up.

## Decisions still needed from the owner

- Confirm the **90-day window** (or set another).
- Confirm whether to **notify maintainers now** or hold until after the Show HN
  (Wave 1) so the named gallery lands as Wave 2.
- Approve the **final target list** once the fresh sweep produces candidates.

## Status tracker

| Target | Commit | Finding(s) | Disclosed (date) | Window ends | Named-publish OK |
|---|---|---|---|---|---|
| _(fill after the fresh sweep)_ | | | | | |

## Guardrails (unchanged)

- No named result publishes before its window ends.
- Every finding is a **configuration default, not an exploited vulnerability**;
  say so explicitly, as the aggregate does.
- If a maintainer asks to be excluded, exclude them; the aggregate already stands
  on its own.
