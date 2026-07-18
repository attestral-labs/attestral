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
| Design-visible recall | **4 / 4 (100%)** |
| Full-set coverage (all 8 advisories) | **4 / 8 (50%)** |
| Out of design-time scope | 4 (all agent-framework dependency CVEs) |
| Taxonomy attempted (covered + partial) | 28 / 32 (88%) |

**Design-visible: 4 of 4.** The four MCP-package advisories (mcp-remote
CVE-2025-6514, apify actors-mcp-server CVE-2026-50143, git-mcp-server
CVE-2025-53107, mcp-atlassian CVE-2026-27826) all fire ATL-117 because their
vulnerable versions are in the known-CVE table. This subset really measures one
thing: **is the CVE table current.** It is only as good as its freshness, which
is exactly what the weekly research radar keeps up (CVE-2026-50143 and the two
newest entries arrived that way). The honest risk here is latency, not blindness.

**Full-set: 4 of 8.** The other four are the interesting half:
`langchain-core` CVE-2025-68664 (LangGrinch, CVSS 9.3), and three `langgraph`
advisories (CVE-2025-67644 SQLi, CVE-2026-28277 deserialization, CVE-2026-34070
path traversal). These are real, high-severity, and **structurally invisible to
a design-time architecture review**: they live in the agent's Python dependency
tree, which Attestral does not ingest. We report them as a named limitation, not
a silent miss. Closing them is a concrete build: a package-manifest ingester
(`requirements.txt` / `pyproject` / lockfile) that emits a `_dependency_versions`
signal the known-CVE mechanism already knows how to check. That is now a roadmap
item, seeded directly by this measurement.

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
2. **It is allowed to be wrong, and is.** 50% full-set coverage is not a number
   you report if you are optimizing for a clean pass. Each miss is itemised with
   its advisory and a concrete path to close it.
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
- **The design-visible subset is small (4).** It will grow with the radar. Do
  not read 100% on four cases as a strong recall claim; read the 50% full-set
  and the itemised gaps as the honest signal.
- **Framework CVEs are marked out of scope, not solved.** "Our design-time model
  cannot see this" is a real limitation, not a defense. The fix (a dependency
  ingester) is on the roadmap, not shipped.
- **The taxonomy mapping is ours.** The status of each item (covered / partial /
  gap) is our assessment against public taxonomies; the taxonomy itself is
  external, the placement is a defensible judgment, not a hand-labelled audit.
