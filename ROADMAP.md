# Attestral roadmap

The metric is **conviction**: does a skeptical security engineer install it, keep
it past the first run, and tell someone. The two things that decide that are
time-to-first-value and false-positive rate - not rule count, not engine novelty.
So the order below is friction-and-noise first, differentiated moat second,
because nobody reaches the moat if they bounce on setup. The research-grounded
uplifts are real, but they are sequenced *after* the table stakes on purpose.

Legend: **size** S/M/L · **who's unconvinced without it**.

## Done

- **M0 - Credibility reframe.** The adversarial-validation output claimed "proof"
  where it shows graph *reachability*. Reframed across the CLI, terminal report,
  and every site page to attack-path feasibility / reachability over the modeled
  graph, with the sound-over-approximation assumption stated explicitly.
  Reachability is now framed as necessary, not sufficient, for exploitation.
- **M-EVAL v1 - Agentic-detection benchmark** (`evaluation/`). Recall, benign
  false-positive rate, and rule coverage, run in CI. First honest numbers on the
  moat surface. Grows toward threat-labelled and adversarial (see M6).
- **Evaluator agent** (`.claude/agents/evaluator.md`) - an on-demand honest
  scorecard weighted to conviction, so this rating is repeatable, not a one-off.

## Phase 0 - Conviction (remove friction and noise)

- **M1 - Zero-config, proven.** *(autodiscovery already works: `attestral scan
  <repo>` finds Terraform, K8s, `.mcp.json`, agent configs and produces
  cross-component findings with no model file.)* Remaining is to **prove** it: a
  90-second "one command, useful output" path front-and-centre in the README and
  the demo GIF, a crisp "found N surfaces across M ingesters" preamble on every
  scan, and an honest note on what it does *not* read (arbitrary agent code - by
  design, this is design review, not SAST). **S · the drive-by evaluator who
  decides in 90 seconds.**
- **M2 - Real-systems gallery.** Run Attestral against 15-20 popular open-source
  MCP servers / agent projects (the `research/mcp-ecosystem` corpus is the seed),
  responsibly disclose, and publish the actual cross-component flows found. One
  screenshot of a genuine lethal-trifecta path in a project people recognize
  converts more skeptics than any table. Doubles as the evaluation corpus and
  feeds M-EVAL. **M · every skeptic who wants proof it works on real code.**
- **M3 - False-positive budget.** Make the FP number a first-class, gated,
  visible contract: per-rule confidence, a benign-corpus FP-rate tracked in CI
  (started in M-EVAL, budget = 0 on benign), `--min-confidence`, and one-line
  inline suppression next to a finding. A noisy scanner gets muted and
  uninstalled; this is the retention lever. **S-M · the engineer on their second
  run.**
- **M4 - Onboarding polish.** `attestral init` in one command, a GitHub Action and
  pre-commit hook that gate a PR out of the box, SARIF into the Security tab, and
  a Claude Code skill/plugin so it is discoverable where agents are built.
  **S · the team lead wiring it into CI on a Friday.**

## Phase 1 - The differentiated artifact (the moat, after table stakes)

The through-line: the differentiation is the signed, verifiable, IFC-grounded
artifact that carries a design from review into enforcement - not the rule count.

- **M5 - Sign the evidence chain.** Move from tamper-evident to tamper-evident
  *and attributable*. A raw SHA-256 chain only means something to whoever already
  holds the true head. Wrap the sealed review in a DSSE envelope, sign with Ed25519
  or Sigstore keyless OIDC, export as an in-toto attestation, optionally anchor the
  head in a transparency log. Slots into the SLSA / Sigstore / in-toto stack
  procurement already recognizes; no MCP-specific design-review attestation has
  shipped yet. **M · auditors and procurement; "hand it to an auditor" is hollow
  until the head is signed.** (Refs: Sigstore, SLSA, in-toto; GitHub artifact
  attestations.)
- **M6 - Information-flow lattice under toxic-flow.** The lethal-trifecta finding
  is heuristic today (named source/sink groups over the graph). Attach
  confidentiality and integrity labels to sources and sinks in the SystemModel and
  the trifecta becomes a defensible property: a high-confidentiality source reaches
  a low-integrity exfil sink without passing a declassifier. Citable and precise
  instead of a severity with an opinion attached; connects to CaMeL / FIDES /
  Progent. This also upgrades M-EVAL toward threat-labelled cases. **M-L ·
  researchers and reviewers who see "heuristic" and discount it.** (Refs: FIDES;
  CaMeL.)
- **M7 - Compile as a provable narrowing.** The compile step already emits a
  default-deny policy; make it a *verified least-privilege* result. Adopt
  Progent's SMT expansion/narrowing check: prove the compiled policy is strictly a
  narrowing of the reviewed model's ambient capability, and classify every
  re-attestation as expansion or narrowing, with expansions forcing re-review.
  Turns "compile to default-deny" into "compile to a policy with a confinement
  guarantee." **L · the buyer who needs the enforcement to be provably faithful to
  the review.** (Refs: Progent 2504.11703; Policy Compiler for Secure Agentic
  Systems 2602.16708.)
- **M8 - Close the design-to-runtime gap on rug-pulls and schema poisoning.** A
  single design-time snapshot structurally cannot see a tool whose description or
  schema is silently changed after approval (the benchmark records this as a known
  gap, `gap-description-rugpull`). Fix it on the runtime side: the drift telemetry
  schema carries the *actual* description and schema served at invocation, hashed,
  and diffed against the attested hash. This is where the mcp-guard integration
  earns its keep and "the review is the policy" becomes a genuine end-to-end
  control. **M-L · anyone who knows tool poisoning is a runtime rug-pull, not a
  tag.** (Refs: Invariant Labs tool poisoning; Microsoft 2026-06-30.)
- **M9 - Memory-entry provenance signing.** Extend M5's signing to memory: make the
  trust label part of a CBOR-canonical record covered by the writer's Ed25519
  signature, so a relabelling attempt produces an entry whose signature no longer
  verifies. Turns the static world-writable / vector-store findings (and the
  uncovered ATL-113) into cryptographic detection. **S-M (after M5) · teams whose
  agents have persistent memory.** (Refs: MemLineage.)

## Phase 2 - Adversarial evaluation (raise the bar on ourselves)

- **M10 - Defense-aware evaluation.** Static-benchmark wins evaporate under
  adaptive attack. Map every agentic finding class to the disclosed 2026 corpus
  (NSA/CISA MCP guidance, CVE-2025-6514, MCPTox, the AgentDojo injection catalog)
  and report precision/recall against it, then run defense-aware attacks against
  Attestral's own detection and publish where it breaks. "Here is where our own
  tool fails under adaptive attack" is the intellectual honesty the field now
  demands - and a stronger story than a clean pass. Builds directly on M-EVAL.
  **L · researchers, and anyone who has watched a static benchmark get gamed.**

## Notes on sequencing

Phase 0 is what earns the right to Phase 1: a signed, IFC-grounded artifact nobody
installs is worth less than a quiet, one-command scanner people keep. Ship the
conviction milestones first; let the benchmark and the gallery carry the proof;
then build the moat on an audience that is already using the tool.
