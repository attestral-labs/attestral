# Attestral agentic-detection benchmark

The moat is agentic detection, so this is where the tool has to be measured. This
harness reports the three numbers a skeptical security engineer actually decides
on - and it runs in CI, so they cannot quietly rot.

```bash
python -m evaluation.score        # prints the scorecard, writes RESULTS.md + results.json
```

## What it measures

| Number | What it answers | How it is labelled |
|---|---|---|
| **Recall** | Of the agentic findings a design *should* raise, how many still fire? | `positive` cases in `cases.yaml`, labelled from each fixture's documented intent (its README) and the cited research. Enforced at 100% in CI - a drop is a regression. |
| **False-positive rate** | On a realistic, well-configured design, how much noise does the tool make? | `benign` cases under `corpus/` - clean fleets that must raise **zero** agentic findings. Enforced at 0 in CI. This is the number that decides whether the tool survives the first run. |
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
(currently one genuine gap - `ATL-113`, world-writable instruction file, has no
fixture yet), and the `gap` cases. As the corpus grows toward real-world systems
(see roadmap M2, the real-systems gallery), positive cases will be labelled from
the *threat* rather than the current output, so recall can legitimately fall below
100% and expose true misses.

## Growing it

- **Add a positive case:** point `path` at a fixture and list the agentic rule ids
  it should raise. Ground the label in the fixture README + a citation.
- **Add a benign case:** drop a realistic clean config under `corpus/` and add it to
  `benign:`. If it raises anything agentic, that is a false positive to fix.
- **Add a real system:** vendor a popular open-source MCP server / agent project,
  scan it, and (responsibly) record the cross-component flows found. This corpus is
  both the evaluation and the gallery.
