# Attestral agentic-detection benchmark

The moat is agentic detection, so this is where the tool has to be measured. This
harness reports the numbers a skeptical security engineer actually decides on -
and it runs in CI, so they cannot quietly rot.

```bash
python -m evaluation.score        # prints the scorecard, writes RESULTS.md + results.json
```

## Two tiers

1. **Synthetic regression** (this folder's `cases.yaml` + `corpus/`): example
   agent designs we wrote by hand, each with an answer key of what it should (and
   should not) raise. This proves the rules keep working and stay quiet on clean
   designs. It is a unit-test suite, not a real-world measurement - recall reads
   100% because we wrote both the designs and the answer key.
2. **Real-world** ([`real-world.md`](./real-world.md) / `real-world.json`): the
   tier tied to reality. attestral run against **33 of the most popular public MCP
   servers** at pinned commits. Aggregate only - no repo is named, because per-repo
   results are under responsible-disclosure embargo. This is where the numbers stop
   being about our own examples: 52% of the servers with a config auto-install an
   unpinned package, 48% expose an unauthenticated remote, 22% carry a lethal
   trifecta, and the 9 newest rules fired on 0 of 33 (a real false-positive read).

The scorecard prints both. The synthetic tier is the regression guard; the
real-world tier is the evidence the detection means something off our own bench.

## What it measures

| Number | What it answers | How it is labelled |
|---|---|---|
| **Recall** | Of the agentic findings a design *should* raise, how many still fire? | `positive` cases in `cases.yaml`, labelled from each fixture's documented intent (its README) and the cited research. Enforced at 100% in CI - a drop is a regression. |
| **False-positive rate** | On a realistic, well-configured design, how much noise does the tool make? | `benign` cases under `corpus/` - clean designs that must raise **zero** findings from any band, agentic or cloud. Enforced at 0 in CI. This is the number that decides whether the tool survives the first run. |
| **Coverage** | Which agentic rules have at least one positive case exercising them? | Derived: the union of labelled findings vs every ATL-1xx/2xx rule. Uncovered rules are printed as coverage debt. |

It also records **known design-time gaps** (`gap` cases): real 2026 threats a single
design-time snapshot cannot see - e.g. a rug-pull where a tool's description is
silently changed *after* approval. Those are detectable only at runtime (drift of
the served description hash vs the attested hash), so they are reported as
limitations, never counted as a pass. Honesty about where the tool does not reach
is the point, not a footnote.

## Why labels aren't circular

`positive` recall is a **regression** guard: it proves the rules keep firing as the
pack evolves, not that the rules are complete. The honest signal about *reach*
comes from three other places: the benign false-positive rate, the coverage number
(every agentic rule now has a positive case - `ATL-113` via the harness's
`world_writable` setup field, `ATL-213` via a `fleet` case that spans two repos
the way `attestral fleet` does), and the `gap` cases. That threat-labelled measurement now exists as **M-EVAL v2**:
`python -m evaluation.score_external` scores eight published CVE-GHSA advisories
labelled from the advisory, not from our output, and reports full-set coverage of
7/8 (allowed to be below 100%) plus a taxonomy denominator. See
[`external-recall.md`](./external-recall.md). This benchmark stays the regression
guard; the external set is the honest-recall companion.

## Growing it

- **Add a positive case:** point `path` at a fixture and list the agentic rule ids
  it should raise. Ground the label in the fixture README + a citation.
- **Add a benign case:** drop a realistic clean config under `corpus/` and add it to
  `benign:`. If it raises anything agentic, that is a false positive to fix.
- **Add a real system:** vendor a popular open-source MCP server / agent project,
  scan it, and (responsibly) record the cross-component flows found. This corpus is
  both the evaluation and the gallery.

## The ML layer's numbers

The rules benchmark above measures the deterministic layer. The ML layer
(`--ml`, prompt-injection scoring on language surfaces) is measured separately:

```bash
python -m evaluation.ml_eval                              # labeled set, installed tiers
python -m evaluation.ml_eval --repos research/mcp-ecosystem/work   # + real-surface FP read
```

`ml_eval` scores through the production code path (same chunking, same default
threshold) against a vendored independent labeled set
(`data/deepset-prompt-injections.jsonl`, Apache-2.0) and, optionally, every text
surface ingested from a directory of real MCP repos. Published numbers and
methodology: [`ml-precision-recall.md`](./ml-precision-recall.md). The heuristic
tier's precision/recall floors are enforced in CI by `tests/test_ml_eval.py`.
