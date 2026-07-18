# What Attestral catches, and what it does not

A security tool you can trust is one that is honest about its edges. In a field
full of overclaiming, the tool that documents where it stops is the one a
skeptical engineer keeps. This is that page: the scope boundaries, the known
blind spots, and where our own detection breaks. None of it is hidden in a
footnote, because the limits are part of the product.

## The one-line scope

Attestral is a **design review**, not a SAST tool. It reads the *declared*
surface, the MCP config, the agent wiring, the system prompts, the Terraform and
Kubernetes, builds a system model, and reasons over it. It does not read the
inside of a tool's implementation. It tells you the capability a tool *grants*
and the flows that capability enables; it will not find a logic bug inside that
tool's code. That is a deliberate boundary, not a gap we are hiding: design-time
review is where the highest-leverage, cheapest-to-fix issues live, and it is a
different job from line-level static analysis.

## What it does not do (by design)

- **It does not execute anything against your live agent.** The adversarial
  validation (`attestral validate`) is a symbolic walk over the model's declared
  edges, plus an optional sandbox harness with a planted canary. It never runs a
  payload against a system you operate. Execution against a fingerprinted,
  own-target-only system stays gated and future.
- **Reachability is necessary, not sufficient, for exploitation.** A reachable
  attack path means the design *allows* the flow over declared capability, a
  sound over-approximation. It does not prove the LLM would follow an injection,
  that no guardrail or human-approval step sits in the path, or that the sink is
  reachable at runtime. We reframed away from the word "proof" for exactly this
  reason. Treat a reachable HIGH as "worth prioritizing," not "already exploited."
- **It reads declared config, not arbitrary application logic.** A secret loaded
  through three layers of indirection, a capability granted at runtime by code we
  do not model, an env var resolved by a wrapper script: these can be missed. The
  scan preamble says this on every run so a clean result never reads as "nothing
  here," only as "nothing in the surfaces Attestral reviews."

## Known blind spots (where we can miss)

- **HCL resolution depth.** The Terraform resolver does not yet evaluate
  cross-variable interpolation, so a misconfiguration behind a `var.` reference
  can sit unseen. This is why the TerraGoat benchmark number is reported as a
  *floor*, gated by resolver depth, not a measure of the cloud pack's reach.
- **Capability classification is coarse on purpose.** Capabilities are inferred
  from substring hints on launch commands and, for agent code, from the symbols a
  tool's body uses. A novel or deliberately obfuscated tool can be misclassified.
  The bias is toward *missing* a capability (one fewer cross-cutting finding)
  rather than a per-server false alarm, because a noisy scanner gets uninstalled.
- **The ML tier is probabilistic.** The prompt-injection classifier (heuristic,
  ONNX, or DeBERTa) can miss a cleverly framed injection and can flag benign
  instructional prose. It is a knob with a tunable threshold, not an oracle, and
  its findings are tagged `origin: ml` so they are never mixed with the
  deterministic core.
- **Agent-code ingestion needs a recognizable shape.** A file is modeled as an
  agent only when it imports a known framework and defines a tool. Agent logic in
  an unrecognized framework, or generated at runtime, will not be modeled.
- **The fleet is what you point it at.** `attestral fleet` models the repos you
  give it. It cannot yet discover an organization's entire agent estate on its
  own, so a cross-repo toxic flow involving a repo you did not include is invisible.

## Where our own detection breaks (adversarial honesty)

Static-benchmark wins evaporate under adaptive attack, so we measure ourselves
against that, not just against fixtures we wrote:

- The `evaluation/` harness tracks a benign-corpus **false-positive rate** in CI,
  budgeted to zero on clean designs, so a rule that starts over-firing fails the
  suite. The real-world sweep of 33 public MCP servers reports the actual
  false-positive read, including the borderline classes we deliberately do *not*
  headline (the Windows `cmd /c npx` idiom read as a shell, benign instructional
  text scored by the heuristic tier).
- A defense-aware attacker who knows our detection can evade it, so we measure
  that directly: `python -m evaluation.adversarial` runs adaptive attacks against
  our own detection and publishes the matrix ([`evaluation/defense-aware.md`](../evaluation/defense-aware.md)).
  Today **half of the eight adaptive attacks evade**: a semantic paraphrase or a
  confusable-homoglyph rewrite slips past the prompt-injection heuristic, and a
  shell hidden inside `node -e` interpreter code or an opaquely named wrapper is
  not seen as a declared shell. The other half hold (base64 and zero-width text
  are decoded; `env`-prefixing and splitting a trifecta across files do not evade
  the fleet model). Both gaps share one root, that we review the *declared*
  design, which is precisely what the compile -> drift runtime loop exists to
  close. The matrix is gated in CI, so a robustness regression fails the suite.

## Reporting and posture

Security issues go to the process in [`SECURITY.md`](../SECURITY.md). The design
commitments there, fail-closed matchers, no `eval` in the rule path, a
deterministic offline-verifiable evidence chain, are testable properties, not
promises. If you find a case where Attestral claims more than it delivers, that
is itself a bug worth reporting.
