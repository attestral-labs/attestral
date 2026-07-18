# External recall, measured (M-EVAL v2)

The [agentic-detection benchmark](./RESULTS.md) reports recall 116/116 (100%).
That number is honest about what it is - a **regression guard** whose positive
labels come from each fixture's own README - but a skeptic is right to discount a
perfect score graded on cases we wrote to trip our own rules. This page answers
the harder question: **how does Attestral do on threats we did not label
ourselves?**

Everything here is reproducible with `python -m evaluation.score_external`; the
machine-readable record is [`external/results.json`](./external/results.json),
and every case cites its advisory in
[`external/cases.yaml`](./external/cases.yaml).

## What was measured

Eight real, published 2025-2026 advisories (CVE + GHSA), each labelled from the
**advisory**, not from Attestral's output. The config for each design-visible
case is reconstructed from the advisory and scanned through the production path
(`build_model` + `RuleEngine`). Recall is allowed to fall below 100%, and it
does.

Cases are classified by what a design-time review can even see:

- **design-visible** - the vulnerable pattern is in declared config an ingester
  reads (here, an MCP server pinned to a known-vulnerable package version).
- **dependency** - a code vulnerability in an agent framework the model does not
  ingest (no package-manifest ingester yet).
- **runtime** - only manifests at run time; a design-time model cannot see it.

## The numbers

| Metric | Value |
|---|---|
| Design-visible recall | **7 / 7 (100%)** |
| Full-set coverage (all 8 advisories) | **7 / 8 (88%)** |
| Out of design-time scope | 1 (a langgraph CVE with no confirmable fixed version) |
| Taxonomy attempted (covered + partial) | 28 / 32 (88%) |

This set is also a worked example of the loop it exists to drive. Its **first
version scored 4/8 (50%)**: it detected the four MCP-package advisories (via the
known-CVE table, ATL-117) and named the other four - agent-framework dependency
CVEs - as a structural gap, because the vulnerability lived in the agent's Python
dependency tree, which no ingester read. That named gap became a build: the
package-manifest ingester (`attestral/ingest/dependencies.py`, rule ATL-145).
With it, three of those four now fire, and coverage rose to **7/8 (88%)**.

**Design-visible: 7 of 7.** The four MCP-package advisories (mcp-remote
CVE-2025-6514, apify CVE-2026-50143, git-mcp-server CVE-2025-53107,
mcp-atlassian CVE-2026-27826) fire ATL-117; three framework advisories
(langchain-core CVE-2025-68664 LangGrinch and CVE-2026-34070 path traversal,
langgraph-checkpoint-sqlite CVE-2025-67644) now fire ATL-145 off a pinned
`requirements.txt`. This subset measures one thing: **are the two known-CVE
tables current**, which the weekly radar keeps up.

**Full-set: 7 of 8, and the residual is honest.** The one miss is langgraph
CVE-2026-28277 (a deserialization RCE that chains from CVE-2025-67644). It is a
real, config-visible dependency vuln, but we could not confirm an exact fixed
version from the public advisory, so it is not in the table - a data gap, marked
out of scope rather than papered over. It stays in the set as the residual, and
it is why coverage is 88% and not 100%.

**Taxonomy: 28 of 32 attempted.** Against an independent denominator - the OWASP
LLM Top 10, the OWASP MCP Top 10, and the OWASP ASI 2026 threat classes
([`taxonomy.yaml`](./taxonomy.yaml)) - 19 items are covered by a rule or the
ML/judge layer, 9 are partial (the config-visible slice only), and 4 are honest
gaps: 2 need an ingester (unbounded consumption, agent resource limits) and 2 are
out of scope by nature (misinformation, cascading hallucination - runtime output
quality, not a design-time property). A perfect score here would mean the
taxonomy was trimmed to fit us; the gaps are the point.

## Why this is not self-graded

Three things make this number trustworthy in a way the 116/116 is not:

1. **The labels are external.** Each case is a published advisory with a CVE, a
   GHSA link, and an affected version. Nothing about the label was chosen to
   match a rule we ship.
2. **It is allowed to be wrong, and was.** The first run scored 50%, which is
   not a number you report if you are optimizing for a clean pass. Each miss was
   itemised with its advisory and a concrete path to close it, and closing the
   biggest one (a dependency ingester) is what moved it to 88% - with the one
   residual still on the board.
3. **It moves as the world moves.** The set grows as advisories land (the radar
   feeds it), so the denominator is not frozen to our advantage. A new
   dependency CVE lowers coverage until the ingester exists; a new MCP-package
   CVE lowers it until the table catches up.

## Reproduce it

```bash
python -m evaluation.score_external            # scorecard + external/results.json
python -m evaluation.score_external --check    # exit 1 if a design-visible advisory stops firing
```

The design-visible cases are a CI regression floor (`tests/test_external_recall.py`):
if a known-CVE-table entry ever stops firing, the suite fails.

## Caveats, all of them

- **Config reconstruction is a judgment call.** For each design-visible case we
  reconstruct the minimal launch config from the advisory; the label is the
  advisory's affected version, cited so anyone can check it.
- **The set is still small (8).** It will grow with the radar. Do not read the
  100% design-visible recall as a strong claim on seven cases; read the 88%
  full-set and the itemised residual as the honest signal.
- **The dependency ingester matches exact pins only.** It flags a
  known-vulnerable version pinned with `==` (or an exact npm pin); an open range
  is left alone, so it under-reports rather than false-flags. A real lockfile
  would tighten this.
- **One residual is a data gap, not a scope gap.** langgraph CVE-2026-28277 is
  config-visible in principle; it is missed only because we could not confirm an
  exact fixed version from the public advisory to put in the table.
- **The taxonomy mapping is ours.** The status of each item (covered / partial /
  gap) is our assessment against public taxonomies; the taxonomy itself is
  external, the placement is a defensible judgment, not a hand-labelled audit.
