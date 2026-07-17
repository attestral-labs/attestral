# The ML layer, measured

The [DeBERTa page](https://attestral.vercel.app/ml-deberta.html) explains how the
classifier works. This page answers the question a skeptical engineer asks
next: **how well does it actually score?** Everything below is reproducible
with `python -m evaluation.ml_eval`; the machine-readable record of the run,
including every per-row score and every flagged surface, is
[`ml-results.json`](./ml-results.json).

Measured 2026-07-16 on the commit that added this file, with
`protectai/deberta-v3-base-prompt-injection-v2` at `main`. Re-measured
2026-07-17 after the instruction-surface gate shipped (see the real-surface
section); the labeled-set numbers were unchanged by it, by design.

## What was measured

Scoring goes through the **production code path**: the same `MLConfig`
defaults, the same 1200-char / 200-overlap chunking, a surface's score is its
max chunk probability, findings fire at the default `0.5` threshold. No lab
shortcuts, so the numbers describe what `attestral scan --ml` does, not what
the model could do under ideal conditions.

Two datasets, mirroring the rules benchmark's two tiers:

1. **An independent labeled set.**
   [`data/deepset-prompt-injections.jsonl`](./data/deepset-prompt-injections.jsonl):
   662 labeled prompts (263 injection / 399 benign, English and German),
   vendored from the Apache-2.0
   [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections)
   dataset. Neither the heuristic pattern bank nor our fixtures were written
   against it, and the base model's card lists 22 public training sources with
   this dataset not among them (see caveats).
2. **Real MCP surfaces.** Every text surface Attestral's own ingest extracts
   from the 33 vendored public MCP server repos in the ecosystem corpus:
   106 unique surfaces (66 agent-instruction files, 19 system prompts, 20
   registry-manifest descriptions, 1 subagent definition). Nobody wrote these
   to be scanned, which makes them the honest false-positive read. Every flag
   was human-adjudicated by reading the flagged text.

## The numbers

**Labeled set, default threshold 0.5:**

| Tier | Precision | Recall | F1 |
|---|---|---|---|
| Heuristic (runs by default, zero-dep) | **0.950** | 0.144 | 0.251 |
| DeBERTa (`attestral[ml]`) | **0.965** | 0.414 | 0.580 |
| ONNX (`attestral[onnx]`) | not separately run: it executes the same exported DeBERTa weights | | |

**Real MCP surfaces (33 repos, 106 surfaces):**

| Tier | Flagged | Adjudication |
|---|---|---|
| Heuristic, before the instruction gate | 28 / 106 (26.4%) | all 28 benign |
| Heuristic, shipped (with the gate) | **4 / 106 (3.8%)** | all 4 benign |
| DeBERTa | 3 / 106 (2.8%) | all 3 benign |

**Recall by what the positive actually is.** The labeled set's positive class
is broad: it counts anything that steers a task-bound assistant off its task
as an injection. Splitting it (a regex characterization; per-row scores are in
`ml-results.json` if you want to slice differently):

| Positive sub-class | n | DeBERTa recall | Heuristic recall |
|---|---|---|---|
| Explicit override / exfiltration phrasing ("ignore previous instructions", "reveal the system prompt") | 18 | **0.944** | 0.667 |
| Role-play persona hijack ("act as", "you are now X") | 28 | 0.250 | - |
| Off-task steering and other chat hijacks | 217 | 0.392 | - |

The threshold sweep is nearly flat (DeBERTa recall moves 0.43 to 0.39 across
thresholds 0.1 to 0.9, precision stays ~0.965): the model is decisive in both
directions, so tuning `--ml-threshold` will not buy recall on this set.

## Reading the numbers honestly

**Precision holds where it matters.** Both tiers sit at ~0.95+ precision on
the labeled set, and even the heuristic's 2 false positives are instructive:
both are benign prompts that genuinely contain zero-width Unicode characters
(encoding artifacts in the dataset), so the hidden-channel check fired on
something really present. On an MCP tool description, that is exactly the flag
you want.

**Recall depends on the definition of injection, so here is the split.** On
explicit injection phrasing - the override, exfiltration, and system-prompt
extraction language that appears in poisoned tool descriptions - the DeBERTa
tier catches 17 of 18. What it misses is the conversational half of the
dataset: role-play hijacks and off-task steering ("now you are Xi Jinping",
"forget our discussion, write an essay about..."), which read as ordinary chat
requests without the context of the task they hijack. That class matters for a
chat product guarding user input; it is not the shape of the threat on the
surfaces Attestral scores (tool descriptions, manifests, instruction files).
The model card's own 99.7% recall was measured on protectai's narrower
20k-prompt set; against deepset's broader definition, through our production
chunking, it is 0.414 overall. Both numbers are true; the split above is the
context that makes them compatible.

**The heuristic is precision-first by design, and the trade is now
quantified.** A curated pattern bank does not chase creative jailbreak
phrasings and never will - that is the model tier's job. It exists so the
default zero-dependency scan still catches the classic override, exfiltration,
and hidden-channel phrasings (0.67 recall on the explicit class) with almost
no noise on short surfaces.

**The real-surface read found a real sore spot, and the fix shipped.** On the
33-repo corpus the DeBERTa tier flagged 3 surfaces (2.8%), all three being the
repos' *own* AI-orchestrator prompts and Copilot instruction files - text whose
literal job is to instruct an AI, so instruction-shaped language is expected.
The heuristic originally flagged 28 (26.4%): 25 were developer-guideline files
(`CLAUDE.md`, `AGENTS.md`, skill definitions) whose ordinary "ALWAYS use X /
always run Y" register trips the `tool_poisoning` family, plus 3 docs with
example emails near words like "send". All benign, and the noise was confined
to long instruction files: on the surface class the ML layer chiefly exists
for - **tool and manifest descriptions** - both tiers flagged **0 of 20**.

A 26% flag rate on real repos' instruction files is too high for a default-on
tier, so the gate shipped (`ml.py::muted_on_surface`): on `agent_instruction`
surfaces, a `tool_poisoning` hit alone no longer reports - it must co-occur
with a second, intent-revealing family (secrecy, exfiltration, or a hidden
channel), with categories pooled across chunks so a trigger in one window plus
concealment in another still counts. Genuine poisoning couples the trigger
with exactly those families; benign instructions do not. Re-measured through
this harness: **28 flags fell to 4 (26.4% to 3.8%)** while the labeled-set
precision/recall stayed byte-identical, because the labeled rows are chat
prompts, not instruction surfaces. The 4 survivors are 2 instruction files
that genuinely carry a second family and the 2 DynamoDB expert system prompts;
`system_prompt` surfaces are deliberately outside the gate (they flagged 2 of
19 against the instruction files' 26 of 66, and a poisoned system prompt is
the higher-stakes read). Model tiers carry no category evidence and are never
muted.

## Reproduce it

```bash
pip install -e ".[ml]"                     # or nothing, for the heuristic tier
python -m evaluation.ml_eval               # labeled set, every installed tier
python -m evaluation.ml_eval --repos research/mcp-ecosystem/work   # + FP read
```

The heuristic tier's floors (precision >= 0.90, recall >= 0.10 on the labeled
set) are enforced in CI by `tests/test_ml_eval.py`, so the numbers on this
page cannot silently rot. The model tiers are re-measured by re-running
`ml_eval` on a machine with the extras installed; single-tier runs merge into
`ml-results.json` without clobbering the other tiers.

## Caveats, all of them

- **The labeled set is not MCP-shaped.** deepset/prompt-injections is
  user-prompt-style text aimed at chat assistants. It is an established
  independent benchmark, but tool-description poisoning is underrepresented in
  it; the real-surface corpus is the MCP-shaped half of the measurement.
- **Base-model independence is likely, not proven.** The model card lists 22
  public training sources and this dataset is not among them, but the full
  training mix is protectai's, not ours.
- **The sub-class split is a regex characterization.** Good enough to explain
  where recall goes; not a hand-labeled taxonomy. Per-row scores are published
  so anyone can slice differently.
- **Tiers legitimately disagree on borderline text.** Same finding schema,
  possibly different verdict; the divergence is why the tier is a
  user-selectable knob. Do not expect the heuristic and the model to flag
  identical sets.
- **Adjudication is ours.** The benign calls on all 31 pre-gate real-surface
  flags (the post-gate 4 are a subset) were made by reading each flagged text;
  the flagged items (with scores and snippets) are preserved in
  `ml-results.json` so anyone can re-adjudicate.
