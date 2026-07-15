# Real-world evaluation: 33 popular public MCP servers

This is the part of the evaluation that is tied to reality. The rest of
`evaluation/` is a synthetic regression suite (example designs we wrote, with an
answer key) that proves the rules keep working. This is different: **attestral
run against 33 of the most widely-used real MCP servers**, at pinned commits.

**Aggregate only.** No repository is named here. attestral reviews the
*documented launch configuration* - the `mcpServers` block users copy from a
README - not the server's source code, and every hit is a **configuration
default, not an exploited vulnerability**. Per-repo results are held under
responsible disclosure until each maintainer has been notified; the named table
and the full reproducible harness publish with that disclosure. The aggregate
below carries no embargo.

## The set

- **33** popular public MCP servers scanned (all scanned OK).
- **23** shipped a committed or README-documented config attestral could model.
  Percentages below are out of those 23.
- **3** of those 23 were clean - a config with zero findings (good counter-examples).

## What their shipped configs contain (192-rule pack)

These are solid, act-on-them findings:

| Pattern | Rule | Repos | % of 23 |
|---|---|--:|--:|
| Auto-installs an unpinned package at launch (`npx -y` / `uvx`) | ATL-105 | 12 | 52% |
| Remote MCP server with no authentication | ATL-109 | 11 | 48% |
| Secret passed to the server via `env` | ATL-104 | 10 | 43% |
| Outbound network / browser access | ATL-107 | 6 | 26% |
| Mutable `@latest` / `:latest` tag (rug-pull surface) | ATL-106 | 5 | 22% |
| **Lethal trifecta** (private data + untrusted input + an exit, in one fleet) | ATL-202 | 5 | 22% |
| Tool server holds cloud credentials | ATL-112 | 2 | 9% |
| Shell execution + outbound network in one fleet | ATL-203 | 2 | 9% |
| Toxic flow (untrusted input can reach a sensitive action) | ATL-207 | 2 | 9% |
| Auto-approve (tool calls run with no human checkpoint) | ATL-108 | 1 | 4% |
| Persistent memory / vector store | ATL-114 | 1 | 4% |

The lethal-trifecta and toxic-flow hits are the headline: they are fleet-level,
compositional risks that exist only once you model several servers (and, in one
case, a committed sub-agent) together - the finding no config-by-config scanner
produces.

## Findings we deliberately do NOT headline (honest caveats)

Intellectual honesty is the point, so these are called out rather than counted
as alarms:

| Pattern | Rule | Repos | Why it is caveated |
|---|---|--:|---|
| Server-name conflict | ATL-206 | 13 (57%) | Usually an artifact of many independent *example* configs in one repo colliding, not one deployed fleet. |
| Prompt-injection text (heuristic ML) | ATL-ML-001 | 12 (52%) | Heuristic tier; a share are benign instructional text, not real injection. Not reported as injection without review. |
| Shell-capable server | ATL-103 | 2 (9%) | Every hit here is the Windows `cmd /c npx …` launcher idiom, **not** a server that intentionally exposes a shell. |
| Non-TLS transport | ATL-101 | 2 (9%) | Both are `http://localhost` **developer** entries in a committed config, not production endpoints. |
| Broad filesystem root | ATL-102 | 1 (4%) | A single scoped `~/.aws` docker mount, not a whole-home root. |

## The false-positive read (the number that decides adoption)

- The **9 newest agentic rules (ATL-125..133)** - MCP sampling/elicitation,
  coding-agent trust flags, registry-manifest secrets, A2A card signing - fired
  on **0 of 33** servers. Correctly: these repos do not ship those surfaces, so
  there is nothing to match. The rules did not spuriously fire on real code.
- **3** real servers with a committed config produced **zero** findings.

## Reproducibility

The scan is run by a harness that shallow-clones each target at a pinned commit
and runs `attestral scan <clone> --format json`. The harness, the exact target
list with commits, and the per-repo results ship together with the maintainer
disclosures and the accompanying write-up. This file is regenerated from that
run; `evaluation/real-world.json` is the machine-readable form.
