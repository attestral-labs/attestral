# Changelog

All notable changes to Attestral. Format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [SemVer](https://semver.org/). This file is enforced: the suite
fails if the package version has no entry here (`tests/test_docs_sync.py`).

## [Unreleased]

### Added
- **ATL-152: committed settings file auto-trusts a plugin marketplace.** A repo-committed
  `.claude/settings.json` that declares an extra plugin marketplace (`extraKnownMarketplaces`) or
  auto-enables plugins (`enabledPlugins`) is a supply-chain grant: a Claude Code plugin silently
  bundles hooks, MCP servers, and subagents, so anyone who opens or clones the repo inherits trust in
  that marketplace and every plugin it serves - the same trust-boundary class as the hooks
  config-injection (CVE-2025-59536) but for the whole plugin bundle, and worst when the marketplace is
  sourced from a raw remote URL. New signals `_declares_plugin_marketplace` / `_remote_plugin_marketplace`
  in `ingest/agent_config.py` (extending the existing settings.json parser), fixture
  `examples/plugin-marketplace-trust`, benchmark case, tests. High severity, cites OWASP-ASI04,
  OWASP-MCP MCP09, CWE-829; surfaced by the research radar (PromptArmor marketplace-plugin hijack, 2026).
- **ML layer: multilingual injection detection in the zero-dependency heuristic tier.** The English
  pattern bank (and the English-first base classifier) is blind to a poisoned tool description written
  in another language. A new `multilingual_override` family adds the instruction-override phrase
  ("ignore the previous instructions") in Spanish, French, Portuguese, Italian, German, Russian,
  Chinese, and Japanese, as multi-word phrases so benign text in the same language (including the
  Chinese "ignore case") does not match. Measured on a new slice
  (`evaluation/data/multilingual-injections.jsonl`): heuristic recall 15/15 across the eight
  languages at 0/7 false positives, up from 0. This also lifted the deepset labeled-set heuristic
  recall from 0.144 to 0.148 (it recovered that set's German injections) at no precision cost.
  `attestral/ml.py`, `evaluation/ml_eval.py` (`multilingual_slice`), floors in `tests/test_ml_eval.py`.
- **ATL-151: secret hard-coded in an agent-instruction file (OWASP LLM07 System Prompt Leakage).**
  An instruction file (CLAUDE.md, `.cursorrules`, AGENTS.md, a skill) that carries a credential-shaped
  value - a provider token, an AWS access key, a private-key block, or a connection string with an
  inline password - leaks it: instruction files are committed to version control, shared, copied into
  logs, and read back into context every run, and the secret cannot be rotated out of the history. The
  value is detected by shape (a provider prefix, a key block, or a long high-entropy assignment that is
  not a placeholder), never guessed, and the generic assignment excludes placeholders and low-entropy
  values so `api_key: <your-key-here>` never fires. New ingester signal `_embedded_secret` in
  `ingest/prompts.py`, fixture `examples/prompt-embedded-secret`, benchmark case, tests. High severity,
  cites OWASP LLM07/LLM02, OWASP-ASI06, CWE-798.
- **ATL-150: tool input schema dereferences an external `$ref` (MCP spec RC 2026-07-28, SEP-2106).**
  Full JSON Schema 2020-12 in tool parameters lets a tool's input schema embed a `$ref` to a remote
  URL, which the spec itself warns clients not to auto-dereference: a client that does pulls
  attacker-controlled schema into the tool definition (schema poisoning - a hidden instruction-bearing
  field description or a new required parameter after review) or is steered into requesting an
  internal URL (SSRF, e.g. a cloud metadata endpoint). ATL-150 statically flags any remote `$ref`
  (http/https/ftp/file/protocol-relative) anywhere in a tool's inputSchema/input_schema/parameters; a
  local `#/...` fragment ref is normal and never flagged. It is the static complement to DRF-005,
  which catches a schema that CHANGES after attestation. New ingester signal `_tool_schema_external_ref`
  in `ingest/mcp.py`, fixture `examples/tool-schema-ref`, benchmark case, tests. High severity, cites
  the MCP spec SEP-2106, SAFE-MCP SAF-T1501, OWASP-ASI04. No MCP scanner checks this surface today.
- **ML layer: permutation-aware cross-tool reassembly (ATL-ML-002).** Tool order is
  attacker-controllable, so a payload split across tool descriptions can be arranged to
  reconstitute under a permutation other than the declared manifest order - the gap the pass's own
  docstring flagged. The reassembly pass now scores each server's tool surface under **both** the
  declared manifest order and a name-sorted order (the highest-value second permutation, an attacker
  who names tools to control alphabetical assembly, without the O(n!) blow-up of trying every
  order), keeps the ordering that reconstitutes the strongest injection, and names it in the
  finding. The same false-positive gates apply per order (no single description clears the
  threshold; the union must clear it by a material margin), so the benign control stays clean. New
  fixture `examples/split-tool-reorder` (reconstitutes only when name-sorted), test in
  `tests/test_ml.py`. `attestral/ml.py`.
- **ML layer: over-defense regression gate (NotInject methodology).** A detector's other
  honesty number is over-defense - firing on benign text just because it carries a trigger word
  (`ignore`, `system`, `execute`, `override`, `jailbreak`, `bypass`), where guard models drop to
  near-random (arXiv 2410.22770). New hand-authored benign-only hard-negative set
  (`evaluation/data/over-defense.jsonl`, 32 rows: feature names that carry a trigger, security
  tools that describe attacks, benign agent instructions, multi-trigger sentences), scored
  through the production surface path (instruction-surface muting applied), with an
  `over_defense_slice` and a CI gate requiring **zero** false positives. Closing it drove a real
  precision fix: the bare word `jailbreak` no longer fires on its own (it now needs a malicious
  context - `jailbreak mode`, `you are jailbroken`, `jailbreak the assistant`), which drops the
  over-defense from 3/32 to **0/32** at no real-injection recall cost (deepset recall unchanged
  at 0.1445, since the DAN / developer-mode / unfiltered patterns still carry the strong cases).
  `attestral/ml.py`, `evaluation/ml_eval.py`, floors + a jailbreak-context unit test in
  `tests/test_ml_eval.py`.
- **ML layer: adversarial-evasion robustness in the zero-dependency heuristic tier.** The
  guardrail-evasion literature (Hackett et al., arXiv 2504.11168) shows leetspeak, separator-spread,
  and hex/decimal/URL/rot13 encoding defeat learned prompt-injection detectors, ProtectAI's model
  included. The heuristic tier now de-obfuscates before matching: it collapses `i.g.n.o.r.e` /
  `1gn0re` and decodes hex, decimal char-codes, URL-encoding, and rot13 (the siblings of the
  existing base64 path), then re-matches - and a de-obfuscated form only ADDS a hit when it reveals
  an injection family the visible text did not, so it surfaces a hidden injection but never inflates
  a benign surface. Measured on a new benchmark slice (`evaluation/data/obfuscated-injections.jsonl`,
  39 obfuscated injections across six families plus 14 benign look-alikes): heuristic recall 36/39
  (0.92) at 0/14 false positives, up from ~0 recall (the bank is ASCII-literal). Guarded in CI on
  the heuristic alone (no model download); the deepset labeled-set precision/recall are unchanged
  (de-obfuscation is a no-op on plain text). Also refreshed the ATL-ML-002 OWASP citations to the
  2026 codes (ASI02/ASI06, MCP03). `attestral/ml.py`, `evaluation/ml_eval.py` (`obfuscation_slice`),
  tests in `tests/test_ml_deobfuscation.py` and a floor in `tests/test_ml_eval.py`.
- **ATL-149: vector/memory store shared across all agent users by one static credential (OWASP
  LLM08).** A vector or persistent-memory server (chroma, pinecone, weaviate, qdrant, pgvector,
  mem0, and the like) reached through a single static credential has no per-tenant boundary, so
  in a multi-user agent one user's query - or a prompt injection steering it - can retrieve or
  poison another tenant's vectors (cross-tenant embedding leakage, the OWASP LLM08 gap). Distinct
  from the public-endpoint confused-deputy case (ATL-115 and the shared-identity fleet rule): this
  isolation gap exists for a purely internal multi-user agent with no exposed endpoint. New
  ingester attribute `_shared_memory_credential` (memory capability plus an env secret; narrower
  than `_shared_static_credential`, which also spans database and saas_data), fixture
  `examples/vector-store-tenancy`, benchmark case, tests. Medium severity, cites OWASP LLM08,
  OWASP-ASI06/03.
- **Coalesced toxic-flow findings: several restatements of one reachability flow read as one
  ranked issue.** On a genuinely bad design, several injectable surfaces that all reach the same
  sinks (a shell, a secret store, an egress channel) each produced a separate critical finding,
  so the top of the report read as one exfiltration flow told N times, which erodes trust in the
  ranking. The terminal report now groups injection-reachability findings that share a
  reachable-sink set into a single block - naming the flow, the sinks, and every surface on it -
  and the severity header shows both the distinct-issue and the raw-finding count
  (`CRITICAL (6 issues · 9 findings)`). This is display only: every finding stays in the list and
  the tamper-evident evidence chain, no count is hidden, and findings with different sink sets
  never merge. `report_terminal.py`, tests in `tests/test_finding_coalesce.py`.
- **Trust-asymmetry escalation for tool shadowing.** A tool-name collision (ATL-204 exact,
  ATL-219 confusable) between two equally-trusted first-party servers is usually a config
  mistake; the same collision between a trusted server and a lower-trust one is the shadowing
  attack itself. This pass raises such a collision one severity band when the colliding
  servers span a trust asymmetry - a mutable `@latest` pin (ATL-106), a remote unauthenticated
  endpoint, or a known-CVE package (ATL-117) on one side and a pinned first-party server on
  the other - and names the lower-trust shadower, exactly as reachability.py escalates a
  finding on a walked chain. A symmetric collision (both pinned) is left at the rule's base
  severity, so the pass raises on the asymmetry, never on the collision alone. Deterministic,
  zero-dependency, idempotent. `attestral/trust_asymmetry.py`, fixture
  `examples/tool-shadowing-trust` (paired control `examples/tool-shadowing`), tests in
  `tests/test_trust_asymmetry.py`.
- **ATL-219: confusable tool-name collision across MCP servers (extends the tool-shadowing
  wave).** ATL-204 catches an exact tool-name clash; an attacker who wants to shadow a
  trusted tool without tripping it registers a look-alike spelling instead - a Cyrillic
  letter for a Latin one, a zero-width space, a case flip, a full-width character. ATL-219
  folds every tool name to the identity a human reads (NFKC, casefold, a bounded homoglyph
  map for the Cyrillic/Greek letters that render as Latin, and removal of zero-width /
  format characters) and fires when two raw-distinct spellings from two different servers
  share a fold, so the two rules never double-count. The fold is deliberately narrow, not a
  fuzzy edit-distance match, so genuinely different names (`list` vs `lists`) never collide.
  Model-level, deterministic, fail-closed. New matcher `model_tool_name_confusable_collision`
  in `rules/engine.py`, fixture `examples/tool-shadowing-confusable`, tests in
  `tests/test_confusable_shadowing.py`. Cites SAFE-MCP SAF-T1301, OWASP-ASI02:2026.
- **Injection-reachability fusion: an injectable surface is only as dangerous as what
  it can reach.** The ML layer scores language surfaces for prompt injection; the
  blast-radius layer scores each surface's if-compromised reach. This pass fuses them:
  a prompt-injection finding (`ATL-ML-001`/`ATL-ML-002`) is raised one severity band and
  annotated with the reachable chain when its surface can reach an actionable sink - an
  outbound channel, a cloud crossing, code execution (ceiling critical), or private data
  (ceiling high) - and is left at its ML severity when it reaches nothing sensitive, so
  the pass escalates by reach, not by the mere presence of injection text. A poisoned
  system prompt that is not itself a tool grant is escalated through the reach of the
  agent runtime it steers. Setting the reachable chain also feeds the OWASP AIVSS score,
  so an injectable-and-reachable surface outranks an injectable dead-end for free. Runs
  on every scan (the heuristic ML tier is always on); idempotent and order-independent
  with the walked-chain reachability pass. Deterministic, zero-dependency.
  `attestral/injection_reach.py`, fixture `examples/injection-reach-demo` (paired control
  `examples/split-tool-poisoning`), tests in `tests/test_injection_reach.py`.
- **Policy property verification: `attestral compile --verify` (addresses #75).**
  `compile` emits the attested design as a policy and `narrowing.classify` proves a
  re-attestation does not widen a prior; this proves ABSOLUTE security properties of a
  single compiled policy - the questions a reviewer asks of an allow-list: no allowed
  server holding a secret can reach an outbound channel (no credential exfiltration),
  no allowed server with code execution can reach an outbound channel (no
  command-and-control), the policy denies by default, and every allowed server is
  TLS-constrained. Each property is reported PROVED or VIOLATED with the exact servers
  that form the counterexample - a witness, not a claim - and because a property is
  proved over the ALLOWED set, denying the offending server is always a way to make it
  hold (so a shell server denied by review turns "no command-and-control" from a hope
  into a proved property). `--fail-on-violation` gates CI. The evaluation is structural,
  deterministic and zero-dependency; the Cedar target has an SMT-backed symbolic
  analyzer that can prove the same properties formally, and `cedar_analyzer_available()`
  reports when it is installed so a formal pass can be layered on - the shipped method
  is always labelled, so a structural check is never mistaken for a formal proof.
  `attestral/policy_verify.py`, tests in `tests/test_policy_verify.py`.
- **Adversarial self-play: proof-of-exploit per reachable path, `attestral validate
  --proof-of-exploit` (closes #82).** The defense-aware eval publishes what Attestral
  misses; this is the complement, demonstrating what it catches. For each reachable
  path it ships three things: the modeled path (deterministic), an LLM-narrated
  exploitation scenario (reused from the tier-1 `redteam.draft_exploit`, gated on a
  key and skipped gracefully without one), and a runnable, gated test that asserts
  the path exists. The safeguard is the point: an LLM narrating an exploit can wander
  off the modeled path and invent a component or a hop the design does not contain,
  so `check_faithfulness` validates the scenario STRUCTURALLY against the model and
  rejects any that names a surface not on the path it claims to exploit. That check
  is deterministic and needs no second model, a stronger guard than an LLM judging an
  LLM because it is grounded in the system model itself. A demonstration aid, never
  an auto-exploit tool: the emitted test asserts reachability, executes nothing, and
  is gated behind `ATTESTRAL_PROOF=1` so it never runs by accident. `attestral/
  selfplay.py`, tests in `tests/test_selfplay.py`.
- **PR security-impact delta: `attestral diff` (closes #80).** The highest-leverage
  place to review an agent design is the pull request that changes it. This builds
  the system model on a base and a head revision and diffs them into a short,
  severity-ranked markdown comment: the capabilities each surface gained, the
  findings and attack paths that opened or closed, and the shift in worst-case
  blast radius. The model diff IS the review - only an assembled system model can
  say "this change gives a secrets-reading server an outbound channel" or "this
  change opens a reachable path from untrusted input to code execution". Short is
  deliberate, because a noisy bot gets muted: a change with no new risk says so in
  one line, and improvements (paths closed, findings resolved) are reported after
  the regressions, never ahead of them. `--fail-on <severity>` turns it into a CI
  gate on newly-introduced risk. Ships with a ready PR-review workflow
  (`examples/github-actions/security-delta.yml`) that posts and updates one
  comment per PR. Deterministic, zero-dependency; `attestral/delta.py`, proof
  fixtures `examples/delta-base` + `examples/delta-head`, tests in
  `tests/test_delta.py`.
- **Blast-radius scoring: `attestral blast-radius` (closes #76).** The rules and
  the attack-path walk answer whether a bad path exists; this answers how bad each
  surface is. For every tool-granting surface it computes the weighted set of
  sensitive capabilities and the cloud crossing reachable from it over the modeled
  design, and ranks the surfaces worst-first, so the lethal-trifecta host and the
  credential-holding server rise to the top on their own and hardening prioritises
  itself. The reach graph makes one honest, stated assumption: co-resident tool
  surfaces are mutually reachable, because once any one is compromised the shared
  agent can be induced to call its siblings (the same action-space premise the
  trifecta detection makes). Each sink class carries a sensitivity weight (code
  execution and a cloud crossing weigh most, persistent memory least) and is
  discounted by hop distance, so a capability a surface holds directly outweighs
  one it can only reach by pivoting. The score feeds OWASP AIVSS as an "Extensive
  blast radius" amplification factor, gated behind the pass so a plain scan's AARS
  is unchanged. Deterministic, zero-dependency; reach is over declared capability,
  a prioritisation signal, not proof of exploitability. `attestral/blast_radius.py`,
  proof fixture `examples/blast-radius-demo/`, tests in `tests/test_blast_radius.py`.
- **ATL-ML-002 (ML tier): fleet-level cross-tool reassembly scoring.** After the
  unchanged per-surface pass, the ML layer now reassembles each MCP server's tool
  descriptions in declared manifest order and scores the union through the same
  tier, threshold, and chunking, catching a Shamir/ShareLock-style tool-poisoning
  payload split across several individually-benign descriptions that per-description
  scoring misses by construction. It is a distinct `origin="ml"` finding with the
  byte-identical schema of ATL-ML-001, gated on the union-vs-max gap: it fires only
  when a server has at least two tool descriptions, no single one clears the
  threshold (so a genuinely-poisoned single tool stays ATL-ML-001 and the two never
  double-count), the reassembled union does clear it, and `union - best_single >=
  fleet_gap` (default 0.25), so a benign long tool set never fires. New knobs
  `MLConfig.fleet_scan`/`fleet_gap`/`fleet_min_tools`; proof fixtures in
  `examples/split-tool-poisoning` (a real split) and `examples/benign-long-toolset`
  (the false-positive control); methodology in `evaluation/ml-precision-recall.md`.
  Reassembly order is attacker-controllable, so v1 commits to declared manifest
  order with a newline join and is honest about that limit.
- **Closed-loop drift remediation: `attestral drift --remediate`.** The self-healing
  half of the runtime loop. `attestral drift` detected runtime divergence from the
  reviewed design; a human then hand-wrote the policy fix. This synthesizes it: given
  the compiled policy and its drift findings, it emits the minimal policy-tightening
  delta that would have prevented each finding - quarantine the offending server
  (`allow: false`, carrying the DRF id as the reason) - re-emitted to BOTH compiled
  targets (mcp-guard and Cedar) from one tightened dict. The safety principle is
  load-bearing: a drift finding means the runtime diverged from the reviewed design,
  so remediation only ever NARROWS the policy toward denial and NEVER widens the
  design to match the drift; a compromised runtime cannot drive its own policy. Every
  delta is verified a narrowing (`narrowing.classify` must be NARROWING or UNCHANGED,
  never EXPANSION) before it is emitted, and it is PROPOSED only - a human approves
  and re-compiles. Terminal-first: the proposed ops and narrowing verdict print to
  the terminal; the re-emitted mcp-guard YAML plus a sibling `.cedar` are written only
  with `-o`. Proven end-to-end in `tests/test_drift_remediate.py`: a DRF-008 stream is
  remediated, and re-running drift over the same events now blocks the attack (DRF-002)
  while `narrowing.classify(original, tightened)` stays a narrowing.
- **`attestral attest` (+ `--verify`): verifiable conformance attestation.** A new
  pipeline stage that binds, into one DSSE-signed in-toto Statement, the reviewed
  design (model hash), the review chain head, a digest and severity summary of the
  findings, the hash of BOTH compiled policies (mcp-guard + Cedar), and, with
  `--runtime`, a digest of the runtime events plus the drift verdict (CONFORM, or
  the DRF ids observed). `attestral attest --verify` recomputes every digest
  offline from the supplied design, re-runs drift on the supplied events, and
  checks the signature, so any tamper - a changed design, a swapped policy, a
  doctored event stream - makes verification FAIL and names the failing step. The
  structure assembly and every hash recompute run with zero dependencies; only the
  signature step needs the `attestral[sign]` extra, so an unsigned attestation
  (all digests still bound) is produced with no install. This is a tamper-evident,
  signature-based conformance attestation, not a formal proof of security: it
  proves the runtime observed matches the design reviewed and the policies compiled
  from it, nothing more. Flagship demo in `examples/attested-agent/`; full shape and
  copyable sequence in `docs/attestation.md`.
- **DRF-008 (drift): unauthorized runtime capability / process spawn.** The
  compiled policy now carries each server's attested capability envelope, and
  drift fires CRITICAL when an attested, allowed server exercises a capability at
  runtime that its envelope never authorized - the opaque-wrapper case (an
  innocuously named launcher that shells out) is caught at runtime even though
  static review cannot see it. Fail-closed: a missing capability field, an
  unmodeled label, or a server with no attested envelope never fires. Adds an
  optional `capabilities` field to the drift event schema (fully back-compatible).
  Proven end-to-end and gated in `evaluation/adversarial.py`.
- **`attestral compile --target cedar`: a second compile target.** Emits a Cedar
  authorization policy over the same attested-design IR the mcp-guard renderer
  uses, so the reviewed design compiles into a policy you can load into AWS
  Verified Permissions or adapt for Amazon Bedrock AgentCore. mcp-guard stays
  the default target, so existing users see no behavior change. Each allowed
  server becomes a `permit` scoped to `MCPServer::"<name>"` with its constraints
  as `when` conditions; each denied server becomes a `forbid` carrying the deny
  reason as a comment; Cedar's native implicit deny covers everything absent.
  Cedar is emitted as pure text with no new dependency; full validation uses the
  external `cedar` CLI, which is intentionally not vendored. See
  `docs/compile-cedar.md`.
- **Agent-to-cloud reachability: ATL-218, agent runtime assumes an admin IAM
  role.** The headline cross-boundary rule no linter can copy. It joins a
  Kubernetes ServiceAccount's IRSA `eks.amazonaws.com/role-arn` annotation
  (cluster boundary) to an AWS IAM role that grants `AdministratorAccess` or a
  wildcard policy (Effect Allow, Action `*`, Resource `*`) on the cloud
  boundary, by ARN-name identity resolution - so any prompt injection or tool
  compromise inside that runtime inherits full control of the account. Two
  ingester edges unlock the join: `terraform.py` gains a cross-resource
  `_resolve_iam_admin` post-pass deriving `_admin_wildcard`/`_role_name`/
  `_role_arn` on IAM roles (resolving inline policies, managed-ARN attachments,
  and standalone policy docs, with fail-closed handling of both literal and
  terraform-address references), and `kubernetes.py` now ingests the
  `ServiceAccount` kind and stamps `_irsa_role_arn` onto each workload. The new
  fail-closed model matcher `model_agent_reaches_admin_iam` fires one finding
  per (agent runtime, admin role) pair, attributed to the workload, and stays
  silent on an admin role no ServiceAccount assumes (a CI/CD or break-glass
  role) and on a scoped, non-wildcard role. Fixtures `examples/agent-admin-iam`
  (positive + built-in break-glass FP guard) and `examples/agent-admin-iam-benign`
  (scoped role, no fire). Pack now 242 (with the radar wave and ATL-218).
- **DeBERTa-tier defense-aware evaluation and the adaptive-paraphrase slice.** The
  defense-aware harness now escalates every language attack to the optional DeBERTa
  tier, measured through the production scan path: the semantic paraphrase the
  precision-first heuristic scores 0.0 the model scores 1.0 (the gap closes on
  escalation), while a base64-smuggled instruction the heuristic decodes and catches
  the model misses (the tiers are complementary, not ranked). Backed by a new
  vendored slice `evaluation/data/paraphrase-injections.jsonl` (15 semantic
  paraphrases of real injection intents plus 12 benign look-alikes): the heuristic
  recovers 0/15, DeBERTa 13/15 at one benign false-positive on twelve, now reported
  by `python -m evaluation.ml_eval` and gated for heuristic precision by
  `tests/test_ml_eval.py`. The DeBERTa escalation matrix is gated by
  `tests/test_adversarial.py` when `attestral[ml]` is installed and skipped cleanly
  otherwise. The DeBERTa page (`website/ml-deberta.html`) gains a live in-browser
  heuristic scorer that shows the tier complementarity interactively and cites the
  character-injection evasion result (arXiv 2504.11168) as the reason the layer
  keeps the heuristic in front of the model. Write-ups: `evaluation/defense-aware.md`,
  `evaluation/ml-precision-recall.md`. No rule-pack change (stays 237).
- **Research radar 2026-07-18 wave (pack 237 -> 241).** Four new rules plus a
  transport broadening from the weekly radar sweep. **ATL-147**: an MCP server
  whose launch args bind `0.0.0.0` is an unauthenticated LAN endpoint a web page
  can drive via DNS rebinding (CVE-2026-59950 / CVE-2026-63118 / CVE-2025-66416 /
  CVE-2026-23744; MITRE ATLAS, OWASP-MCP MCP07, NIST SC-7). **ATL-148**: an MCP
  server that forwards the caller's inbound credential downstream (token
  passthrough), an identity crossing distinct from a generic secret-in-env
  (OWASP-MCP MCP01, OWASP-ASI03, NIST IA-5). **ATL-069**: an `aws_launch_template`
  backing an ASG or EKS node group that does not enforce IMDSv2, the pod-to-node-
  role theft rung that `aws_instance`-only IMDS checks miss (CIS AWS 5.6, CIS EKS,
  NIST AC-6/SC-7). **ATL-338**: an AKS cluster that leaves local accounts enabled,
  a static admin kubeconfig that bypasses Entra ID (CIS AKS, NIST AC-2/IA-2).
  **ATL-133** now also flags the deprecated WebSocket transport, not just SSE
  (MCP SEP-2596, CVE-2026-59950).
- **Closed two of the M10 evasions (ATL-146 + confusables normalization).** The
  defense-aware eval found four adaptive attacks that evaded detection; two are
  now closed and the harness proves it (evasion rate 50% -> 25%, gated by
  `tests/test_adversarial.py`). (1) **Confusable homoglyphs**: the ML heuristic
  now normalizes Cyrillic/Greek look-alikes to their ASCII skeleton before
  scoring (NFKC + a curated confusables map), so "Ignоre аll prеvious..." scores
  like its plain form, with no false positive on genuine non-Latin text. (2)
  **Shell hidden in interpreter inline code**: new rule **ATL-146** fires when a
  launch runs an interpreter (node/python/ruby/...) with an inline-eval flag and
  code that spawns a process (`child_process`, `os.system`, subprocess,
  backticks) - a shell capability that declares no shell token and so evaded
  ATL-103. The derived `_shell_via_interpreter` also adds the `shell` capability
  so the fleet-level combos see it. Fixture `examples/interpreter-shell`. The
  remaining two evasions (semantic paraphrase, an opaque wrapper's body) are
  documented as fundamentally beyond a design-time heuristic, with their real
  mitigations named (the DeBERTa tier; the compile -> drift runtime loop). Pack
  236 -> 237.
- **Defense-aware evaluation (roadmap M10): adaptive attacks on our own
  detection.** A static benchmark scores well by construction; this measures the
  opposite. `python -m evaluation.adversarial` takes designs Attestral does
  detect, applies the transformations an adaptive attacker would use to hide the
  same malice, and reports which evade. The honest result is published in
  `evaluation/defense-aware.md`, and the matrix is gated: `--check` (run by
  `tests/test_adversarial.py`) fails if any outcome diverges, so a robustness
  regression, or a silently closed gap, is caught. `docs/limitations.md` links
  the result.
- **Memory-entry provenance signing (roadmap M9): a trust label you cannot
  flip.** Extends the M5 evidence-chain signing to agent memory. An agent's
  long-term memory is a poisoning target, and the classic attack is relabelling:
  mark untrusted content trusted (or insert an entry claiming a trusted writer)
  so injected text becomes authoritative on a later, unrelated run. The static
  findings see the surface (ATL-112 memory store, ATL-113 world-writable,
  ATL-214 poisoning flow); this makes each entry cryptographically accountable.
  `attestral/memory.py` binds an entry's trust label to its content with the
  writer's Ed25519 signature (the same DSSE pre-auth encoding as the chain
  signature). `attestral memory verify STORE --keyring writers.yaml` audits a
  store against a keyring of trusted writers: a relabelled or edited entry
  (MEM-001, critical), an unknown writer (MEM-002), or a trust claim with no
  signature (MEM-003) is reported, while an untrusted entry passes as the safe
  default. `attestral memory sign` authors an entry. Fixture
  `examples/signed-memory/`; write-up `docs/memory-signing.md`; tests in
  `tests/test_memory.py`. CI now installs the `sign` extra so the signing and
  memory-provenance crypto is exercised, not skipped.
- **Schema poisoning is now pinned and caught (roadmap M8).** The rug-pull pin
  (`manifest.py`, DRF-005) already covered each tool's name and description; it
  now also covers each tool's **input schema**. A tool whose `inputSchema` gains
  a hidden parameter or an instruction smuggled into a field description after
  approval now flips the manifest hash and fires DRF-005 at runtime, closing the
  schema-poisoning half of the design-to-runtime gap the benchmark records as
  `gap-description-rugpull`. The schema is accepted under any of `inputSchema`
  (MCP spec), `input_schema`, or `parameters`, canonicalized so object-key order
  does not matter, and pinned only when a tool declares one, so an existing
  schema-less attestation's hash is unchanged (no spurious drift). The shared
  canonicalization means both the attested (ingest/compile) and observed (drift)
  sides get it symmetrically. Drift telemetry can carry the served `inputSchema`
  in its `manifest` object; docs updated. Tests in `tests/test_manifest.py` and
  `tests/test_drift.py`.
- **Claude Code plugin + `attestral init` scaffolds it (roadmap M4).** Attestral
  now ships as an installable Claude Code plugin, so it is discoverable where
  agents are actually built: `/plugin marketplace add attestral-labs/attestral`
  then `/plugin install attestral@attestral-labs`. The bundled `attestral-review`
  skill teaches Claude Code when to run a scan (a new or edited MCP server, agent
  prompt, or tool), how to read the findings, and how to gate CI. `attestral
  init` also scaffolds that skill into a project's `.claude/skills/`, alongside
  the existing GitHub Action, pre-commit hook, and waivers file, so a team gets
  the review reflex in their own repo. The scaffolded CI gate now filters to the
  high-confidence, zero-FP-on-benign set (`--min-confidence high`), so a
  probabilistic ML hit can never break a build by default. Plugin at `plugin/`
  with `.claude-plugin/marketplace.json`; tests in `tests/test_init.py`.
- **False-positive budget (roadmap M3): per-rule confidence and
  `--min-confidence`.** Recall says "we catch the real ones"; this says "and we
  don't cry wolf." Every finding now carries a `confidence` (high | medium |
  low). Deterministic rules are `high` by contract (structural, zero false
  positives on the benign corpus); the ML tier's confidence tracks its
  probability, so a borderline injection hit is `low` and can be filtered while
  a clear one stays; a rule can opt down (the ATL-201 boundary advisory is
  `low`). `attestral scan --min-confidence high` keeps only the CI-safe set and
  reports how many lower-confidence findings it dropped. The confidence surfaces
  as a tag in the terminal report (only when below high, so default output stays
  clean) and as a SARIF result property. The benign-corpus zero-FP promise is a
  gated contract: `tests/test_fp_budget.py` fails if `--min-confidence high`
  ever fires on a benign design. Write-up `docs/false-positive-budget.md`.
- **Inline suppression: `// attestral:ignore ATL-xxx` waives a finding in
  place.** The waiver file stays the heavyweight, expiring, provenance-pinned
  path; this is the one-line path for the everyday false positive. A marker in
  the config a finding came from, naming its rule, waives it - kept in the
  evidence chain (waived, not deleted), tagged with the marker's file and
  optional `reason:`, so an auditor still sees the suppression. Matched by (rule
  id, source file) and fail-safe: a marker that matches nothing does nothing.
- **MCP ingester now parses JSONC.** Real Claude Desktop / Cursor / VS Code
  configs carry `//` and `/* */` comments; a strict `json.loads` silently
  dropped the whole file the moment one appeared (and blocked inline
  suppression). `attestral/ingest/_jsonc.py` strips comments in a string-aware
  way - the `//` in a URL survives - and nothing else, so a genuinely malformed
  config still fails loudly. Tests in `tests/test_jsonc.py`.
- **Compile as a narrowing (roadmap M7): `attestral compile --against`.** The
  compile step already emits a default-deny policy; this makes it a confinement
  guarantee. `--against PRIOR` compiles the current design and classifies the
  re-attestation as a NARROWING, UNCHANGED, or EXPANSION of the prior policy's
  capability envelope (servers, capability sets, transport/root/secret
  constraints, manifest pins). An expansion - a new server, a tool that gained a
  capability, a loosened constraint, a dropped or changed manifest pin - names
  each widening and exits non-zero, so a CI gate blocks a design that grants more
  ambient capability than the reviewed one until a human re-baselines. The policy
  now records each server's attested capability set. Honest scope: a structural,
  fail-closed containment check (`attestral/narrowing.py`), not an SMT proof;
  SMT-level confinement is the future strengthening. Write-up `docs/narrowing.md`;
  tests in `tests/test_narrowing.py`.
- **IFC integrity endorser: a human-approval gate clears ATL-217's integrity
  half.** The declassifier gave the confidentiality dimension its mitigation; this
  is the symmetric twin for integrity. The MCP ingester derives
  `_requires_approval` when a shell/exec sink is gated behind human approval (the
  positive inverse of the auto-approve signal, the fix ATL-203/207 recommend),
  matched conservatively against explicit approval tokens. When every
  trust-critical sink is approval-endorsed, an injected command cannot run
  uninterrupted, the integrity half of the information-flow violation is broken,
  and ATL-217 clears - while the coarse ATL-203/207 still fire. The two lattice
  dimensions now have separate, correct mitigations: an egress allowlist does not
  clear integrity, and approval does not clear confidentiality. Fixture
  `examples/ifc-endorsed`; tests in `tests/test_ifc.py`; `docs/ifc.md` updated.
- **IFC declassifier: an egress allowlist clears ATL-217 while ATL-202/207 still
  fire.** The M6 lattice promised that a modeled mitigation would clear the
  precise finding; this delivers the first one. The MCP ingester derives
  `_egress_allowlisted` when an outbound tool constrains its reach to an
  allowlist (the fix ATL-202 recommends), matched conservatively so a bare
  `--allow` never over-clears. When every egress sink is allowlist-declassified
  the confidentiality half of the information-flow violation is broken and
  ATL-217 clears, while the coarse heuristics ATL-202/207 still flag the raw
  capability co-occurrence - the precise-vs-heuristic difference the lattice
  exists for. The integrity half is unaffected (an allowlisted fetch tool still
  ingests untrusted content; an endorser signal is the next step). Fixture
  `examples/ifc-declassified` (allowlisted, ATL-217 silent) against
  `examples/vulnerable-agent` (unrestricted, both fire); tests in
  `tests/test_ifc.py`.
- **Information-flow lattice (roadmap M6): ATL-217, the trifecta as a defensible
  property.** The lethal-trifecta (ATL-202) and taint-flow (ATL-207) findings are
  heuristic - named capability groups co-occurring. `attestral/ifc.py` attaches
  confidentiality and integrity labels to every tool surface, so the same flow
  becomes a formal property: a high-confidentiality source reaching a
  low-confidentiality egress sink (data leaves the boundary), or a low-integrity
  source reaching a trust-critical sink (untrusted input drives an action), with
  no declassifier or endorser on the path. ATL-217 fires with the named label
  path, making the finding citable (FIDES / CaMeL) instead of a severity with an
  opinion. The lattice is future-correct: a modeled declassifier clears the flow
  while the coarse ATL-202/207 still fire - the difference is the roadmap's next
  step. Engine matcher `model_ifc_violation`; tests in `tests/test_ifc.py`;
  write-up `docs/ifc.md`. Pack 235 -> 236.
- **Dependency-manifest ingester + ATL-145 (agent dependency with a known CVE);
  external recall 50% -> 88%.** `attestral/ingest/dependencies.py` reads
  `requirements.txt` / `pyproject.toml` / `package.json`, and a pinned
  known-vulnerable version fires ATL-145 - the same known-CVE mechanism ATL-117
  gives MCP servers, now over the agent's own dependency tree, the surface a
  config-only review misses. The curated table uses exact affected version
  ranges (branch-precise: langchain-core CVE-2025-68664 fixed on 0.3.81 and
  1.2.5, CVE-2026-34070 fixed on 1.2.22, langgraph-checkpoint-sqlite
  CVE-2025-67644 fixed on 3.0.1) and matches only an exact pin, so an open range
  never false-flags. This is the build M-EVAL v2 seeded: it closes the framework
  gap the external recall set exposed, lifting full-set coverage from 4/8 to 7/8
  (the residual is one langgraph CVE with no confirmable fixed version). Fixture
  `examples/vulnerable-deps`; tests in `tests/test_dependencies_ingest.py`. Pack
  234 -> 235.
- **M-EVAL v2: threat-labelled external recall (recall you cannot self-grade).**
  The regression benchmark scores 116/116 because its labels come from each
  fixture's own README. `evaluation/external/cases.yaml` labels from published
  advisories instead: eight real 2025-2026 CVE-GHSA cases scored through the
  production path by `evaluation/score_external.py`. Design-visible recall is
  4/4 (MCP servers pinned to known-vulnerable versions all fire ATL-117), but
  full-set coverage is 4/8 (50%) and allowed to be: the other four are
  agent-framework dependency CVEs (LangGrinch CVE-2025-68664, three langgraph
  advisories) a design-time model cannot see without a package-manifest
  ingester, itemised as a named gap rather than a silent miss. Adds
  `evaluation/taxonomy.yaml` (OWASP LLM/MCP Top 10 + ASI 2026 threats -> 28/32
  attempted) as an independent denominator, a CI floor
  (`tests/test_external_recall.py`) that fails if a known-CVE advisory stops
  firing, and the write-up `evaluation/external-recall.md`. Two newly-verified
  advisories added to the known-CVE table (git-mcp-server CVE-2025-53107,
  mcp-atlassian CVE-2026-27826).
- **Research radar wave, 2026-07-17 (pack 232 -> 234).** ATL-144 (AWS Bedrock
  AgentCore runtime role left attached to the `BedrockAgentCoreFullAccess`
  quickstart policy, which grants account-wide AgentCore actions including
  `GetWorkloadAccessTokenForUserId`, a caller-controlled workload-token mint)
  and ATL-434 (GCP workload identity pool provider with no `attribute_condition`,
  so any subject the external IdP issues can federate into the pool). Plus
  CVE-2026-50143 (`@apify/actors-mcp-server` <= 0.10.10, URL-authority injection
  that exfiltrates the Apify bearer token) added to the known-CVE table behind
  ATL-117. Fixtures `examples/agentcore-iam` and the gcp-pack workload-identity
  resource; both rules ship a fires-and-a-clean-negative test. Sourced from the
  weekly automated research radar.
- **Four cloud rules from the research radar sweep (pack 228 -> 232).** ATL-067
  (CloudTrail trail with logging switched off, an audit trail that records
  nothing), ATL-068 (GuardDuty detector declared but disabled), ATL-337 (Azure
  SQL Server accepting TLS below 1.2), and ATL-433 (Cloud SQL instance with
  automated backups disabled). Each cites a real CIS/NIST/FSBP control and ships
  with an isolated fixture (examples/aws-pack-ext, azure-pack, gcp-pack) and a
  test asserting it fires alone.
- **The benchmark has no review limbo and no coverage debt.** All ten unlabelled
  fires were adjudicated: every one was a documented true positive whose label
  was missing (`agent-fleet-flows` per-component checks, `agentic-risks` fleet
  flows ATL-214/216, `mcp-supply-chain` ATL-109), none was a precision bug. The
  last two uncovered agentic rules gained positive cases through two typed
  harness fields in `cases.yaml`: `fleet:` builds one model spanning repos the
  way `attestral fleet` does (exercises ATL-213) and `world_writable:` sets the
  o+w bit for the duration of the scan, since git cannot store it (exercises
  ATL-113). The scorecard now reads 116/116 recall, 0 false positives, 59/59
  agentic coverage.
- **The benchmark's benign tier now counts every rule band.** A benign design
  must be quiet across the whole pack, not just the agentic bands - a cloud
  false positive gets the tool muted just as fast. New benign case
  `benign-open-egress` (scoped ingress + world egress, the standard Terraform
  shape) locks the ATL-002 regression into `python -m evaluation.score`.
- **TerraGoat regression suite** (`tests/test_terragoat.py`): runs against the
  vendored deliberately-vulnerable corpus when present (skipped otherwise -
  `research/` is untracked). Pins the per-provider detection floor, exact
  ATL-002 = world-open-ingress equivalence, the egress-idiom non-finding, and
  that agentic rules stay silent on a pure-IaC repo.

### Fixed
- **Security-group CIDR matching is direction-aware (kills the first-scan false
  positive on real Terraform).** The ingester collected `cidr_blocks` from any
  nested block, ingress or egress, into one `_cidr_blocks` union, so ATL-002
  ("Security group open to the world", HIGH, an *ingress* rule by its own
  description) fired on the near-universal default-outbound idiom
  (`egress { cidr_blocks = ["0.0.0.0/0"] }` and `aws_security_group_rule` with
  `type = "egress"`). Both parse tiers now attribute every CIDR to a direction -
  from the enclosing `ingress`/`egress` block, or a rule resource's resolved
  `type` - and emit `_ingress_cidr_blocks` / `_egress_cidr_blocks` alongside the
  union. ATL-002 matches ingress only; a CIDR whose direction is not statically
  decidable stays union-only and never becomes an ingress finding (fail closed).
  ATL-032 (the default SG must hold *no* rules) deliberately keeps the
  direction-blind union.

## [0.18.0] - 2026-07-17

### Added
- **Signed evidence chain: `attestral sign` (from tamper-evident to authentic).**
  The SHA-256 chain is tamper-evident but not authentic: an attacker could edit a
  finding, recompute the whole chain and a new head, and `verify` would still say
  VALID. `attestral sign` signs the chain head with an Ed25519 key inside a DSSE
  envelope (the Sigstore / in-toto envelope), and `attestral verify --public-key`
  now checks both integrity (no entry altered) and authenticity (this is the
  chain the key holder sealed, not a recomputed forgery). `--gen-key` makes a
  keypair; `sign` refuses a chain that is already broken. Signing needs the new
  `attestral[sign]` extra (`cryptography`, lazy-imported); the integrity check
  still runs with zero dependencies. New `attestral/signing.py`; tests in
  `tests/test_signing.py`.
- **The ML layer's precision/recall, measured and published.**
  `evaluation/ml_eval.py` scores every tier through the production scan path
  against a vendored independent labeled set (`deepset/prompt-injections`,
  Apache-2.0, 662 rows) and the 106 real surfaces ingested from the 33-repo
  MCP ecosystem corpus, with every flag human-adjudicated. Results:
  heuristic 0.950 precision / 0.144 recall, DeBERTa 0.965 / 0.414 (0.944
  recall on explicit injection phrasing); real-surface flags 28/106 vs 3/106,
  all benign. Full write-up in `evaluation/ml-precision-recall.md`, cited on
  the site's DeBERTa page; the heuristic's floors are enforced in CI
  (`tests/test_ml_eval.py`).
- **Kubernetes ingester expansion.** The K8s ingester now parses RBAC and
  network resources into first-class components: `k8s_rbac_role` (Role /
  ClusterRole, with wildcard-verb, wildcard-resource, and secrets-access
  signals), `k8s_rbac_binding` (RoleBinding / ClusterRoleBinding, with a
  cluster-admin-binding signal), and `k8s_network_policy` (default-deny
  detection). Pod and container hardening signals were added too: AppArmor
  profile, SELinux options, service-account name, a plaintext-secret-in-env
  detector, and a pod-level fallback for `runAsUser` so root is caught when it
  is set only at the pod level.
- **Six Kubernetes rules (ATL-530..535), pack 222 -> 228.** AppArmor explicitly
  unconfined (ATL-530), a secret hardcoded in a container env var (ATL-531),
  RBAC roles with wildcard resources (ATL-532) or wildcard verbs (ATL-533),
  RBAC access to Secrets (ATL-534), and a binding to the built-in cluster-admin
  role (ATL-535). Each cites its CIS Kubernetes control and ships with a
  fixture under `examples/k8s-hardening` and `examples/k8s-rbac`.
- **Ecosystem-composite fixture: one realistic project, every layer, known
  answers.** `examples/ecosystem-composite` composites the patterns the 33-repo
  public corpus actually exhibits into a plausible AI support-desk product and
  scans it as a known-answer test: 33 deterministic findings across cloud,
  Kubernetes, MCP supply chain, and the cross-boundary flows (with one attack
  path walked end to end), 4 seeded language positives across both ML tiers,
  and 2 negative controls that stay clean, including a benign `CLAUDE.md` that
  scores 0.75 raw and is correctly muted by the new instruction-surface gate.
  Benchmarked in the site's "Verified end to end" section.

### Changed
- **Heuristic ML tier: instruction-surface gate (26.4% real-repo flag rate down
  to 3.8%).** On `agent_instruction` surfaces (`CLAUDE.md`, `AGENTS.md`,
  `.cursorrules`, skill files) a `tool_poisoning` pattern hit alone no longer
  reports: imperative agent-directive phrasing is that file's ordinary register
  ("when asked to commit, first run the tests"), and it flagged 26 of 66 real
  repos' instruction files, every one adjudicated benign. The hit now counts
  only when a second, intent-revealing family co-occurs on the surface -
  secrecy, exfiltration, or a hidden channel - with evidence pooled across
  chunks (`ml.py::muted_on_surface`). Re-measured through `evaluation/ml_eval.py`
  on the 33-repo corpus: 28/106 flags fell to 4/106 while labeled-set
  precision/recall was untouched (0.950/0.144). Tool and manifest descriptions,
  system prompts, and the model tiers (which carry no category evidence) are
  outside the gate.
- **Site: the three review layers each get a dedicated deep-dive.** The landing
  page gains an interactive terminal that runs each layer (deterministic, ML,
  LLM-judge) against the same insecure agent with the real command output; new
  `deterministic.html` and `judge.html` field-notes pages, and the DeBERTa page
  gains a supervision section (proper supervised fine-tuning and weak
  supervision from the rule packs). Nav consolidates to a single "Review
  layers" entry.
- **`attestral validate --fail-on-reachable` prints `REACHABLE`, not `PROVEN`.**
  The walk demonstrates reachability in the modeled design; the FAQ renounced
  the word "proof" and the CI gate line now matches the epistemics.

## [0.17.0] - 2026-07-16

A large release: the attest-compile-drift loop becomes end to end, the review
gains cross-repo and code-defined-agent reach, severity gets defensible, and the
rule pack grows from 192 to 222.

### Added
- **AWS service-coverage rules (210 -> 222).** Twelve CIS-AWS / AWS FSBP checks
  extending the pack to more services: a public Lambda function URL (ATL-055),
  RDS without IAM auth (ATL-056), Redshift not forcing VPC-routed traffic
  (ATL-057), ElastiCache without at-rest (ATL-058) or in-transit (ATL-059)
  encryption, an unencrypted DocumentDB cluster (ATL-060), SageMaker notebooks
  with direct internet (ATL-061) or root (ATL-062) access, an ALB without
  deletion protection (ATL-063) or invalid-header dropping (ATL-064), an
  unencrypted Kinesis stream (ATL-065), and an unauthenticated API Gateway
  method (ATL-066). Fixtures in `examples/aws-pack-ext/`; tests in
  `tests/test_aws_pack_ext.py`.
- **Kubernetes hardening rules (206 -> 210).** Four more CIS-K8s / Pod Security
  checks against signals the ingester already emits: second-tier
  kernel-tampering capabilities disjoint from the famous six (ATL-526), the
  deprecated `gitRepo` volume (node-RCE, CVE-2024-10220 / CVE-2025-1767,
  ATL-527), out-of-tree `flexVolume` host drivers outside the CSI security model
  (ATL-528), and app workloads colocated in `kube-system` / `kube-public` with
  control-plane RBAC (ATL-529). The K8s pack is now at its ceiling on the
  current ingester surface; further Pod Security controls (AppArmor, SELinux,
  serviceAccountName, env/secretKeyRef, RBAC/NetworkPolicy ingestion) need new
  ingester signals first. Fixtures in `examples/k8s-pack-ext/`; tests in
  `tests/test_k8s_pack_ext.py`. Three more agentic checks,
  each backed by a new ingester-derived signal so the rule stays pure data:
  agent settings that pre-approve unrestricted command execution (`allow`
  includes `Bash(*)` / bare `Bash` / `*`, ATL-141, `_permissive_allow`); an A2A
  card that requires auth but via a long-lived static `apiKey` instead of
  short-lived OAuth tokens (ATL-142, `_weak_auth_scheme`); and a published
  registry manifest that pins a package to a mutable version (`latest` or none,
  ATL-143, `_has_mutable_pin`). Each is precise: a scoped `Bash(git status)`, an
  OAuth scheme, and an exact version pin all pass clean. Fixture
  `examples/agent-supply-trust`; tests in `tests/test_trust_supply_signals.py`;
  all three registered in the `evaluation/` benchmark.
- **Agentic hardening + fleet-flow rule wave (193 -> 203).** Ten new
  research-grounded agentic checks, biased entirely to the moat. Seven
  per-component: an MCP server installed straight from a Git/URL source
  (ATL-134), pulling packages from a non-default registry (ATL-135), disabling
  TLS certificate verification (ATL-136), launched with container
  isolation-breaking flags (ATL-137), exposing a Node inspector/debug port
  (ATL-138), or reached over plaintext WebSocket (ATL-140); plus a code-defined
  agent that grants shell/command execution (ATL-139). Three cross-boundary
  flows only the system model can see: untrusted input written into agent
  long-term memory (memory poisoning, ATL-214), a sampling-capable server
  sharing a runtime with autonomous tool execution (covert invocation, ATL-215),
  and indirect prompt injection that can reach cloud credentials (ATL-216).
  Anchored to the OWASP Top 10 for Agentic Applications 2026 (ASI02/03/04/05/06),
  the OWASP MCP Top 10 2025 (MCP04/05/06/07), OWASP LLM01/05/06, MITRE ATLAS, and
  Unit 42's MCP sampling research. Two new engine matchers
  (`model_sampling_covert_invocation`, `model_injection_reaches_cloud`), both
  fail-closed with tests. New fixtures `examples/mcp-supply-chain/` and
  `examples/agent-fleet-flows/`; tests in `tests/test_supply_chain_flow_rules.py`;
  all ten registered in the `evaluation/` benchmark.
- **Continuous drift: `attestral drift --stdin` / `--watch` (M13).** Point-in-time
  drift becomes a running sidecar. A new stateful `DriftMonitor` observes one
  runtime event at a time and returns only the new drift it triggers, so
  `--stdin` reads a live mcp-guard telemetry pipe and `--watch` tails the event
  log, both streaming drift the moment it happens: an unattested server, a
  denied invocation, a rug-pull (a served tool schema that no longer matches the
  attested manifest, fired once per change), a runaway loop, or a call-volume
  overrun (each budget fires once, when it crosses). Continuous beats
  point-in-time for anything claiming runtime awareness, and it is what makes
  "the review is the policy" an end-to-end control rather than two snapshots.
  New `DriftMonitor` in `attestral/drift.py`; tests in `tests/test_drift_monitor.py`.
- **Structured remediation: `attestral remediate` (M9).** The source-side twin
  of `attestral fix`. For each finding it reads the rule's own matcher and the
  component's real value and prints the concrete edit to make in the source: a
  boolean security flag to flip (`set publicly_accessible = false`), a bad value
  to replace (`http://... -> https://...`), a control to add, tied to the file
  the component came from. Derivation is deterministic and honest: model-level
  findings and ingester-derived (`_`-prefixed) attributes fall back to the
  rule's recommendation rather than inventing a field edit. New
  `attestral/remediate.py`; tests in `tests/test_remediate.py`.
- **Compile-the-fix: `attestral fix` (M10).** For each active finding, compile
  the exact mcp-guard control that neutralizes it, an explanation, and a
  verification verdict, all bound to the review's evidence-chain head. Two honest
  verification kinds: a compositional fleet finding is `re-synthesized` (the fix
  isolates a capability, the model is re-built without it, and the finding no
  longer fires, proven deterministically), and a per-server structural finding is
  `enforced-at-proxy` (a TLS-only / forbid-env-secrets / egress-allowlist / deny
  constraint mcp-guard applies at invocation). `--rule` narrows to one rule; `-o`
  writes the merged controls as a policy slice. A remediation that is also an
  enforceable runtime control is the payoff of the attest-compile-drift loop and
  the thing a linter structurally cannot offer. New `attestral/fix.py`; tests in
  `tests/test_fix.py`.
- **Cross-repo fleet modeling: `attestral fleet` (M12, flagship).** Agentic risk
  lives in the integration - a shell tool in one repo and an untrusted-input
  tool in another are each fine alone but together are an attack chain no
  per-repo scanner can see. `attestral fleet <repoA> <repoB> ...` merges several
  repos into one system model (tagging each component with its repo) and runs
  the full review over the union. New rule **ATL-213** fires only when the
  fleet's combined capabilities complete an attack chain that no single repo
  completes alone, naming which repo supplies the entry, the pivot, and the
  exfiltration; reachability escalation then raises a finding in one repo because
  another repo completes its chain. The detection lives in the rule engine
  (keyed on the `_repo` tags the fleet builder writes) so it is a real,
  documented, `explain`-able rule, inert on ordinary single-repo scans. New
  `attestral/fleet.py`; fixtures `examples/fleet-repo-{reader,runner}`; tests in
  `tests/test_fleet.py`. Capability-granting component types are now centralized
  as `TOOL_GRANTING_TYPES`, so MCP servers, subagents, and code agents all feed
  the fleet analysis uniformly.
- **Ingest agents defined in code, not just config (M11).** Most agents are
  wired in Python, so a config-only scanner sees a minority of deployments. A
  new `attestral/ingest/agent_code.py` AST-parses Python and models each file's
  agent surface as a `code_agent` component whose `_capabilities` are read from
  the tools it defines - `@tool` / `@function_tool` functions (capability
  inferred from the symbols the body uses: `subprocess` -> shell, `requests` ->
  network, a DB driver -> database, ...) and raw Anthropic/MCP tool dicts
  (classified from name + description). Because the capability vocabulary is the
  same one the MCP ingester emits, the fleet rules, attack-path synthesis,
  reachability escalation, and AIVSS all fire on agent code with **no new
  rules** - the lethal trifecta across a shell tool and an egress tool is the
  same flow whether declared in `.mcp.json` or three `@tool` functions.
  Precision over recall: a file is modeled only when it imports a known agent
  framework (Anthropic, OpenAI Agents SDK, LangChain/LangGraph, CrewAI, AutoGen,
  Pydantic AI, MCP/FastMCP) and defines at least one tool, and parsing is
  fail-open. The capability-granting component types are now centralized as
  `TOOL_GRANTING_TYPES` so every analysis sees code agents uniformly. Fixture in
  `examples/code-agent`; tests in `tests/test_agent_code.py`.
- **Delightful PR action: `md-summary` format + baseline-gated workflow.** A new
  `attestral scan --format md-summary` renders a compact GitHub-flavored summary
  - the reviewed surface, each reachable attack path as entry -> pivot ->
  impact, and a findings table naming each finding's reachability - built for a
  PR comment or `$GITHUB_STEP_SUMMARY`. The scaffolded `attestral init` workflow
  now uploads SARIF for inline annotations, writes this summary to the job
  summary, and gates on **net-new** findings only (`--baseline` + `--fail-on
  high`), so a brownfield repo adopts without failing on day-one debt. Under a
  baseline the summary reflects what the change introduced. New
  `render_pr_summary` in `evidence.py`; tests in `tests/test_pr_summary.py`.
- **Zero-config discovery preamble (M1).** Every scan now opens with what
  autodiscovery found ("Reviewed N components across M source files:
  <families>") and an honest note that a design review reads declared config and
  agent wiring, not arbitrary application logic - so a clean scan reads as
  "clean", never "it did not look". `render_discovery` in `report_terminal.py`.
- **Risk acceptance as an audit record (`attestral accept`).** Accepting a
  finding is now itself an evidence-chain record, not just the absence of an
  alert. `attestral accept <path> <rule> <component> -r "why"` appends a waiver
  carrying provenance - who accepted (git identity), when, why, the evidence
  chain head of the review - plus a `finding_sha256` content pin over the rule,
  component, severity, and reachable chain as accepted. If the risk later
  changes (a rule wave re-rates it, or a new tool completes an attack chain
  through the component), the pin stops matching, the acceptance goes stale,
  and the finding comes back until the current risk is re-accepted. The
  suppressed finding carries `waived_by`/`waived_at` into the evidence chain,
  the markdown report, and the SARIF suppression justification. Hand-written
  waivers keep working unchanged; the file's leading comment block survives
  appends.
- **Reachability-based severity (`attestral/reachability.py`, on by default).** A
  severity band is defensible when the reviewer can see why. When a finding's
  component sits on an attack chain the symbolic walk shows reachable in the
  modeled design, the finding now carries that chain (`path: internal chain:
  web -> ops -> web · this component: entry+impact`) and is raised one severity
  band, capped at the chain's own severity (internal = high, external =
  critical). Deterministic, zero-dependency, runs on every scan; findings off
  every chain are never downgraded, because the absence of a modeled path is not
  evidence of safety. Reachable findings also score the full OWASP AIVSS threat
  multiplier (1.0). The chain and any escalation are recorded in the finding -
  and therefore in the evidence chain, the markdown report, and SARIF severity -
  and `attestral compile` applies the same raised severities, so a finding a
  reachable chain lifts to critical denies its server in the runtime policy too.
- **Baseline / diff-aware scanning (`attestral scan --baseline <file>`).** A
  brownfield repo's first scan can surface hundreds of pre-existing findings, and
  a wall of day-one debt gets a scanner uninstalled. `--baseline` records the
  current finding set once (fingerprint = `rule_id::component_id`, the identity
  waivers key on); later scans then report only findings NOT in the baseline - the
  net-new issues a change introduced - so a team can adopt on a large existing
  codebase and gate CI on what a PR actually adds. `--update-baseline` re-records.
  New `attestral/baseline.py`; tests in `tests/test_baseline.py`.

### Changed
- **Adversarial validation reframed from "proof" to reachability.** The `validate`
  walk shows an attack path is *reachable in the modeled graph* (over declared
  capability, a sound over-approximation) - a necessary, not sufficient, condition
  for exploitation. The CLI, terminal report, and every site page now say so
  explicitly, and each non-empty report states the assumption. Overclaiming
  "proof" of exploitability to a security audience is the fastest way to lose it;
  the honest framing is more credible, not less. `--fail-on-reachable` is the new
  flag name (`--fail-on-proof` stays as a deprecated alias). No logic changed.

### Added
- **Agentic-detection benchmark (`evaluation/`).** The moat is agentic detection,
  so it is now measured. `python -m evaluation.score` reports recall on labelled
  positive cases (regression: every labelled finding must fire), the
  false-positive rate on benign designs (the noise number that decides adoption),
  and agentic-rule coverage, plus known design-time gaps (rug-pull-class threats a
  static snapshot cannot see). Enforced in CI via `tests/test_evaluation.py`
  (recall 100%, benign false positives 0). First honest numbers on the moat
  surface; grows toward threat-labelled and adversarial cases (see ROADMAP.md).
- **Real-world evaluation tier (`evaluation/real-world.md` + `real-world.json`).**
  The benchmark now includes a tier tied to reality: attestral run against 33 of
  the most popular public MCP servers at pinned commits. Aggregate only (no repo
  named; per-server results are under responsible-disclosure embargo). Of the 23
  that shipped a modelable config, 52% auto-install an unpinned package, 48% expose
  an unauthenticated remote, and 22% carry a lethal trifecta; the 9 newest agentic
  rules fired on 0 of 33 (a real false-positive read). Borderline finding classes
  are called out with caveats, not headlined. `python -m evaluation.score` prints
  this alongside the synthetic regression tier.
- **ROADMAP.md** - an adoption-ordered roadmap: conviction (time-to-first-value,
  false-positive rate) first, the differentiated signed/IFC-grounded artifact
  second, with the research-grounded uplifts (signed evidence chain, information-
  flow lattice, provable policy narrowing, runtime rug-pull drift) sequenced after
  the table stakes.
- **MCP capability-abuse + coding-agent-trust rule wave (ATL-125..128).** Two new
  ingester signals feed four design-time rules grounded in this quarter's primary
  research:
  - `mcp.py` now surfaces `_declared_capabilities` - the protocol capabilities a
    server config *declares* (distinct from the coarse reachability `_capabilities`
    set). **ATL-125** flags a declared `sampling` capability (a server that can
    spend the user's model tokens and steer tool calls; Unit 42, 2025-12) and
    **ATL-126** a declared `elicitation` capability (deceptive user-prompt channel;
    "When MCP Servers Attack", 2025-09).
  - `agent_config.py` now surfaces `_bypass_permissions` and
    `_auto_enable_project_mcp` from a committed `.claude/settings.json`. **ATL-127**
    flags a permission mode that bypasses the approval prompt (CVE-2026-33068) and
    **ATL-128** flags `enableAllProjectMcpServers`, which auto-starts every
    project-declared MCP server without consent (CVE-2026-21852).
  - Both signals fail closed: absence of the config key never fires. Fixtures:
    `examples/mcp-capabilities`, `examples/coding-agent-trust`. Tests:
    `tests/test_capability_trust_rules.py`.

- **New design-time surfaces: A2A card hardening + MCP Registry manifests
  (ATL-129..133).**
  - The A2A agent-card ingester now reads card *signing* and *OAuth flow*
    structure. **ATL-129** flags a card still offering the OAuth2 implicit/password
    grants removed in A2A 1.0, and **ATL-130** flags a publicly-invocable card with
    no `signatures[]` (a peer cannot verify it is authentic).
  - A new `ingest_registry` reads MCP Registry `server.json` manifests (schema
    2025-12-11) as `mcp_registry_manifest` components. **ATL-131** flags a
    credential baked into the published manifest (a secret variable/header carrying
    a literal value), **ATL-132** a secret-named variable left without `isSecret`
    (so nothing redacts it), and **ATL-133** a deprecated HTTP+SSE transport
    (SEP-2596). Content-gated so an unrelated `server.json` is never mistaken for a
    manifest. Fixtures: `examples/a2a-hardening`, `examples/mcp-registry`. Tests:
    `tests/test_registry_a2a_rules.py`.

### Changed
- **Framework citations refreshed to the current agentic standards.** The legacy
  `OWASP-AgSec` (T1-T15) tags are fully retired in favour of the finalized
  **OWASP Top 10 for Agentic Applications 2026** (`ASI0N:2026`), and the MCP rules
  now also carry the new **OWASP MCP Top 10** codes (`MCP0N:2025`). MCP
  transport/auth/supply-chain/shadowing rules additionally cite the **NSA CSI on
  MCP security** (05/2026) and the new MITRE ATLAS agentic techniques (rug pull
  `AML.T0109`, tool poisoning `AML.T0110`, poisoned-tool publish `AML.T0104`), and
  the `MCP Security Best Practices` references move from the 2025-06-18 to the
  current 2025-11-25 spec revision. Citations are audit artifacts; no detection
  logic changed. The ML tier's prompt-injection finding migrates to `ASI01:2026`.

## [0.16.0] - 2026-07-14

### Added
- **Deeper adversarial validation on `attestral validate`.** Three capabilities
  on top of the symbolic proof:
  - `--action-space` enumerates the tool-call sequences the fleet can be induced
    into (behavioral modeling), not just the one collapsed kill chain.
  - `--remediate` gives the minimal fix for each proven path, each **verified by
    re-synthesis**: strip the rung, rebuild the model, confirm the path is gone.
    A fix that drops the path count to zero is *proven* to close it, not merely
    advised. Each fix also reports the **risk-posture delta** - the worst OWASP
    AIVSS agentic score (AARS) before vs after - and fixes are ranked by how far
    they lower it, so the highest-leverage change comes first. Deterministic; the
    original model is never mutated.
  - `--generate` (opt-in, needs an API key) has an LLM draft the *predicted*
    exploit for a proven path - injection shape, tool-call sequence, transcript -
    labeled predicted, never executed, scoped to the design you own. Graceful
    skip without a key.
  - `--execute` (tier 2, sandbox) replays a proven path through Attestral's own
    stub tools with a planted canary, moving the marker from a stub secret store
    to a captured sink and recording the transcript. Deterministic; no real
    system, secret, or network is touched. Execution against your own live target
    stays gated and future. Tests: `tests/test_redteam.py`.

## [0.15.0] - 2026-07-14

### Added
- **Agentic AI Risk Score (`attestral scan --aivss`).** New `attestral/aivss.py`
  scores agentic findings with an OWASP AIVSS Agentic AI Risk Score (AARS) and
  ranks them, mapping each to an OWASP Agentic (ASI) / LLM Top-10 category. AARS
  measures agentic amplification, a different axis from CVSS severity, so a
  compositional fleet risk like the lethal trifecta outranks a high-CVSS but
  contained one. The score also flows into the **SARIF export** (result `rank`
  0-100 plus a `properties.aivss` block, so it orders GitHub Code Scanning) and
  the **JSON report** (a separate `aivss` key), kept out of the evidence chain so
  its hashes stay reproducible. The terminal ranking is opt-in via `--aivss`.
  Tests: `tests/test_aivss.py`.

### Changed
- **Findings are de-duplicated** by (rule, component): a server discovered in
  several configs no longer inflates the count with identical rows, so the total
  reflects distinct issues.
- **Prompt-injection scoring runs by default.** The zero-dependency heuristic ML
  tier now runs on every `attestral scan`, so language surfaces (MCP tool
  descriptions, system prompts, agent-instruction files) are checked for prompt
  injection without a flag. It stays deterministic and offline. `--no-ml`
  disables the layer; `--ml` or `--ml-engine onnx|deberta` (or
  `ATTESTRAL_ML_ENGINE`) opts into the model-grade tiers. Findings still carry
  `origin: ml` and are scored, never hard-blocked. This changes the default
  finding count on fixtures with planted injection text (e.g. `vulnerable-agent`
  now reports 16, memory-poisoning 1); the fixture-README sync guard includes the
  heuristic tier accordingly.

## [0.14.0] - 2026-07-14

### Changed
- **LLM-as-judge, reworked for reliability**: the judge now defaults to
  `claude-opus-4-8` with adaptive thinking and a schema-constrained verdict
  (structured outputs on supported models), so a well-formed result is
  guaranteed rather than parsed hopefully. A `--judge-panel N` run is now a real
  cross-examination, each panelist reviews through a distinct adversarial lens
  (exploitability, compensating-control false positive, blast radius) instead of
  polling one identical prompt N times. Errors are no longer swallowed: a fatal
  error (bad key, no model access) stops the run and is reported with the real
  message, and any finding a transient error leaves unverified is surfaced. New
  `--judge-effort` (low..max) tunes rigor per run.

### Added
- **Adversarial validation, tier 0 (`attestral validate`)**: a new command and
  `attestral/redteam.py` module that walks each assembled attack path over the
  model's own edges and turns it into a *proof of traversability* - naming the
  capability at each rung and the trust boundaries the walk crosses - then
  commits it to the evidence chain as a `redteam`-origin finding
  (`ATL-RT-EXTERNAL`/`ATL-RT-INTERNAL`). Symbolic tier: deterministic, zero-dep,
  no execution, no network; a design with no complete path proves nothing (an
  attestable negative). The generative and executed tiers build on the same
  proof schema (`research/adversarial-validation-spike.md`). Tests:
  `tests/test_redteam.py`.
- **Guardrails-consistency review**: the agent-config ingester now parses NeMo
  Guardrails configurations (`rails:`/`colang_version`/engine-bearing `models:`
  YAML, with explicit negatives for Kubernetes, compose, waiver, and MCP files)
  into `guardrails_config` components with derived rail attributes. Two rules
  reason over them: **ATL-212 (high)** pairs a rails config with an
  auto-approved shell-capable tool - the rails govern the dialog channel while
  execution runs outside it, a contradiction neither file shows on its own -
  and **ATL-124 (medium)** flags rails that declare input flows but no output
  flows, so replies leave un-railed (OWASP LLM05:2025, NIST SI-15). Fixture:
  `examples/guardrails-gap/`.
- **Shared-identity data access (ATL-211, high)**: a new model-level
  `model_shared_identity_reach` matcher pairs a publicly callable A2A endpoint
  with a data-access server that reaches its store through one static service
  credential (`_shared_static_credential`, derived by the MCP ingester when a
  server has env secrets plus a database/memory/saas_data capability). Every
  external caller reads with the same downstream identity, so per-caller
  entitlements cannot be enforced at the store; the remediation is per-caller
  token exchange (RFC 8693). Neither side is a finding alone - only the system
  model sees the pair. Fixture: `examples/rag-shared-identity/`.
- **Azure AI Search exposure (ATL-336, high)**: flags
  `azurerm_search_service` with public network access enabled - for agent
  stacks this is the RAG retrieval index as a knowledge-base exposure and
  poisoning surface.
- The MCP ingester's memory/vector-store capability hints now also recognize
  `pgvector` and `faiss` backends.

## [0.13.0] - 2026-07-13

### Added
- **Website data regeneration scripts**: the architecture page's embedded code
  graph and the docs page's baked payloads are now generated, not hand-baked.
  `scripts/render_codegraph.py` re-extracts the module graph from
  `.codegraph/codegraph.db` (plus an `ast` sweep that classifies lazy imports
  by position, fixing flags the original bake got wrong) and re-injects it into
  `website/architecture.html`; `scripts/render_docs_data.py` regenerates the
  searchable rule index and the evidence-chain demo entries in
  `website/docs.html` from the live rule packs and a real scan of
  `examples/demo-project`. Both support `--check` as a drift guard and are part
  of the release routine, like the fixture README re-scans.
- **Interactive docs page**: `website/docs.html` now opens with a tabbed
  terminal showing real captured output for the full loop (scan, explain,
  compile, drift, verify), ships a searchable, filterable index of every
  built-in rule with `attestral explain`-style detail cards, and an
  evidence-chain tamper demo that recomputes the SHA-256 chain in the browser
  with the exact algorithm `attestral verify` uses. Also fixes stale content:
  the drift table now documents DRF-001 through DRF-007, the scan flag table
  covers `--local`, `--ml`, `--judge`, `--waivers`, `-q`, and the `aibom`
  format, and the roadmap no longer lists shipped HCL resolution as future
  work.
- **Internal attack paths**: the path synthesizer now also assembles the
  *internal* kill chain, where the entry is a tool that ingests
  attacker-influenceable content (a web fetcher, a SaaS reader, a memory store)
  rather than an external A2A endpoint: untrusted input → code execution →
  exfiltration or cloud. The terminal report renders both external and internal
  chains in the "Attack paths" block, labelled by kind. The internal chain is a
  rendered synthesis, not a new finding: ATL-207 (toxic flow) and ATL-203
  (shell + network) already gate it, so a third finding would be noise. This is
  the majority case, since most agent setups have no A2A endpoint. Fixture:
  `examples/internal-attack-path/`.
- **ML layer explainer**: `docs/ml-deberta.md` walks through what DeBERTa is,
  the ideas behind it (disentangled attention, ELECTRA-style pre-training), and
  exactly how Attestral wires it into the prompt-injection scoring path.
- **Cross-server attack-path synthesis (ATL-210, critical)**: a new `attestral/
  paths.py` synthesizer assembles individual 2-way findings into a complete,
  named kill chain - an externally-reachable A2A endpoint (entry) → a
  code-execution tool (pivot) → an exfiltration channel or cloud credential
  (impact), all in one runtime. Where the per-component rules see the rungs,
  ATL-210 traces the whole ladder and names every hop (`external agent via
  public A2A endpoint [X] → code execution [Y] → exfiltration [Z]`). It fires
  only on a genuinely complete path (all three stages) and the pivot may come
  from a subagent tool grant, not just an MCP server. New fail-closed
  `model_attack_path` matcher. Fixture: `examples/attack-path/`;
  `examples/multi-agent/` gains the assembled chain on top of its rungs.

### Changed
- The "Attack paths" report block header no longer uses a decorative glyph.
- Product output follows the house style everywhere: `attestral verify` prints
  `chain VALID` / `chain INVALID - report has been altered` with no glyphs, the
  markdown report's no-active-findings line loses its glyph, and the em dashes
  in ATL-210's finding detail and ATL-505's description are now plain hyphens.

## [0.12.0] - 2026-07-13

### Added
- **External → cloud reachability across the A2A boundary (ATL-209, critical)**:
  a new fail-closed `model_external_cloud_reach` matcher fires when an
  effectively-public A2A endpoint shares a runtime with a tool server that holds
  cloud credentials (`_has_cloud_credentials`) - an external agent can reach the
  card, delegate a task, drive the cloud-credentialed tool, and pivot into the
  cloud account (`caller → endpoint → tool → cloud`). This is the anti-pattern
  the A2A / RFC 8693 scoped-token-exchange guidance exists to prevent, and it
  extends the agent↔cloud moat to the inter-agent boundary. Fixture:
  `examples/a2a-cloud-reach/`. (Grounded: the AgentCard spec carries no
  downstream-agent field, so a multi-hop *delegation graph* isn't statically
  modelable - but this external→cloud path is, from components already ingested.)
- **A2A inter-agent depth (OWASP ASI07)**: the A2A ingester now distinguishes
  `securitySchemes` (auth *defined*) from `security` (auth *required*), per the
  AgentCard spec, and captures the exposed skill surface. New **ATL-123** flags
  a card that declares schemes but requires none - a public agent that looks
  protected. New **ATL-208** (cross-boundary, critical) fires when an
  effectively-public A2A endpoint fronts a runtime whose tools carry a sensitive
  capability (shell/filesystem/database/memory/saas_data): an external agent can
  reach internal tools through the endpoint - the inter-agent analogue of the
  lethal trifecta, via the new fail-closed `model_external_agent_reach` matcher.
  Fixture: `examples/a2a-exposure/`. The existing `examples/multi-agent/` fixture
  now also flags ATL-208 (its unauthenticated card fronts a filesystem + shell
  fleet).

## [0.11.0] - 2026-07-13

### Added
- **AI-BOM export** (`attestral scan <path> --format aibom -o inv` →
  `inv.cdx.json`): the agent stack as a CycloneDX 1.6 inventory. Stdio MCP
  servers and subagents become `components` (with `pkg:npm`/`pkg:pypi` purls
  when the launch pins a package version, capability classes, and the
  canonical manifest SHA-256 that DRF-005 enforces at runtime); remote MCP
  servers and A2A agent cards become `services` with their real
  `authenticated` state and `x-trust-boundary`; instruction/prompt surfaces
  are `data` components; the delegation/tool-access graph is the
  `dependencies` entry. Cloud resources are deliberately excluded - they
  belong in an infrastructure SBOM. Findings say what is wrong; the BOM says
  what is there.
- **Multi-agent delegation modeling**: Claude Code subagent definitions
  (`.claude/agents/*.md`) are ingested as `subagent` components whose
  frontmatter `tools:` grants derive capabilities (Bash → shell,
  WebFetch/WebSearch → network, Read/Write/... → filesystem), and the
  fleet-level rules (ATL-202/203/207) now reason over the **delegation
  closure** - an MCP fleet with no shell still completes shell+network through
  a delegate, and the finding names the chain (`filesystem via notes; network
  via deploy-bot`). Wildcard delegates (no `tools:` key) are flagged as
  excessive agency (**ATL-120**) but deliberately contribute no capabilities -
  unknown grants are never guessed into findings. Shell-granted delegates are
  **ATL-119**. A2A agent cards (`.well-known/agent-card.json` / `agent.json`)
  are ingested as `a2a_agent` components: no declared `securitySchemes`/
  `security` is a public agent (**ATL-121**, OWASP-ASI07) and a plaintext
  `http://` endpoint is **ATL-122**. Fixture: `examples/multi-agent/` - its
  MCP fleet is safe on its own; every fleet finding exists only across the
  delegation hop.
- **Static HCL resolution** in the Terraform ingester: `var.x` resolves from
  `variable` defaults overridden by `terraform.tfvars`/`*.auto.tfvars` (root
  modules only, per Terraform semantics), `local.x` resolves iteratively,
  `"${..}"` interpolations substitute when fully decidable, and **local
  `module` calls are instantiated** once per call under their real Terraform
  address (`module.<name>.<type>.<rname>`) with call inputs overriding module
  defaults (registry/git modules skipped; cycles cut; depth bounded). This is
  the multiplier that makes the cloud rule pack fire on real-world repos, not
  just literal-value fixtures. Fail-open contract: anything not statically
  decidable stays exactly as written - resolution adds provable findings,
  never guessed ones. Both parse tiers (python-hcl2 and the dependency-free
  scanner, which now also strips inline comments) resolve identically.
  Fixture: `examples/hcl-resolution/` - no risky literal anywhere; every
  finding requires resolution.

## [0.10.0] - 2026-07-13

### Added
- **Known-CVE MCP package detection** (ATL-117): an embedded, curated advisory
  DB flags a server launched at a package version with a published CVE, using a
  real version-range check - e.g. `mcp-remote@<=0.1.15` (CVE-2025-6514, OS
  command injection to RCE). Unpinned/patched versions are not flagged.
- **Agent hook config-injection detection** (ATL-118): a new `agent_config`
  ingester parses `.claude/settings.json`-style settings and flags hooks that
  run shell commands - the config-injection class behind CVE-2025-59536 in
  Claude Code, where a repo-supplied settings file executes code on trust.
  Fixture: `examples/hook-injection/`.

## [0.9.0] - 2026-07-13

### Added
- **Cloud IaC expansion to 146 rules** across AWS/Azure/GCP/Kubernetes, hitting
  the ~150 high-signal CIS-check target. Rules now live in modular
  `rules/<provider>_pack.yaml` files auto-loaded by the engine: **AWS** +28
  (ATL-027..054: S3, IAM, VPC, Lambda, CloudFront, Redshift, OpenSearch,
  DocumentDB, EKS, SageMaker, MSK, Kinesis, ElastiCache, and more), **Azure**
  +19 (ATL-317..335: storage, Key Vault, Cosmos DB, Redis, ACR, App/Function
  apps, AKS, Service Bus, Event Hub), **GCP** +19 (ATL-414..432: Compute, GKE,
  Cloud SQL, Storage, BigQuery, Cloud Functions/Run, DNSSEC, IAM, KMS), and
  **Kubernetes** +15 (ATL-511..525: Pod Security Standards - runAsNonRoot,
  seccomp, capability drops, service-account token automount, host namespaces,
  probes, and more, with additive derived attributes in the K8s ingester).
  Total pack: **169 rules**.
- **Agent skills scanning** (ATL-116): `SKILL.md` skill manifests are ingested
  as agent-instruction components, so world-writable skills (ATL-113) and
  injection text in skills are already covered; ATL-116 additionally flags a
  skill whose `allowed-tools` frontmatter grants shell/exec or wildcard access
  (excessive agency in a shareable, auto-loaded artifact). Closes the
  agent-skills coverage gap versus Snyk Agent Scan / Cisco AI Defense.
- **Confused-deputy / token-passthrough detection** (ATL-115, MCP Security Best
  Practices 2025-06-18): a network-reachable MCP server that also holds a
  downstream credential (secret in env or a forwarded auth/token header) is
  flagged - it can be induced to spend that delegated authority for an attacker
  or pass the token onward. New derived attribute `_confused_deputy`.
- **Toxic-flow / taint-path detection** (ATL-207, Kim et al. 2026 R3): a new
  fail-closed `model_taint_flow` matcher fires when the fleet contains a server
  that ingests untrusted external content (network/SaaS/memory - taint source)
  and a server that executes commands (taint sink), naming the actual source
  and sink servers. The flow is recorded as `taint_source`/`taint_sink` edges in
  the model (and thus the attested hash) - the structural signal a per-resource
  linter can't produce. Closes the information-flow gap from the threat-model doc.
- **R7 resource-drain / DoS budgets** (Kim et al. 2026 R7): the compiled policy
  now carries a tunable `budgets` block, and `drift` enforces it against runtime
  telemetry - a runaway tool-call loop (**DRF-006**: consecutive identical calls
  past `loop_repeat_threshold`, or a same-tool run with varying arguments past
  2x) and per-server call volume over `max_calls_per_server` (**DRF-007**, for
  attested servers). Budgets fail closed on malformed values and a budget of 0
  is enforced, not ignored. Closes the first open gap from
  docs/agentic-threat-model.md.

### Fixed
- Hardened the v0.9 additions after an adversarial review pass: ATL-115 no
  longer flags a correctly-authenticated remote server (a client auth header is
  inbound auth, not a downstream credential); drift budgets fail closed on
  non-integer values instead of crashing; DRF-006 only counts *consecutive*
  runs (no false positives from spaced-out identical calls) and now also catches
  varying-argument loops; DRF-007 ignores unattested servers; and the
  `model_taint_flow` matcher fails closed on a non-list spec.

## [0.8.0] - 2026-07-12

### Added
- **Azure cloud-parity wave** (CIS Microsoft Azure Foundations + CIS AKS
  grounded): the Azure band grows from 8 to 16 high-signal rules - storage
  infrastructure encryption off (ATL-309) and TLS below 1.2 (ATL-310); Key
  Vault public network access (ATL-311); SQL database transparent data
  encryption off (ATL-312); App Service not HTTPS-only (ATL-313); Linux VM
  password authentication (ATL-314); AKS local accounts enabled (ATL-315);
  and PostgreSQL flexible server public network access (ATL-316). Fixture:
  `examples/multicloud-k8s/azure.tf`.
- **Agent-security SoK mapping** (Kim et al., _The Attack and Defense Landscape
  of Agentic AI_, arXiv:2603.11088, 2026): the agentic rule pack is mapped to
  the survey's V1-V6 attack vectors and R1-R7 risk taxonomy in
  [docs/agentic-threat-model.md](docs/agentic-threat-model.md), with
  `Agentic-SoK 2026 <code>` framework citations on the mapped rules. New rule
  **ATL-114**: persistent agent memory / vector stores are detected (new
  `memory` capability class) as memory-poisoning targets (V6) and now count as
  private data toward the ATL-202 lethal-trifecta exfiltration chain.
- **GCP cloud-parity wave** (CIS GCP Foundations + CIS GKE-grounded): the GCP
  band grows from 5 to 13 high-signal rules - Compute full cloud-platform scope
  (ATL-406), IP forwarding (ATL-407) and non-Shielded VMs (ATL-408); GKE
  non-private nodes (ATL-409), non-Shielded nodes (ATL-410) and client-cert
  auth (ATL-411); public bucket IAM to `allUsers` (ATL-412); and KMS keys
  without a rotation period (ATL-413). Fixture: `examples/multicloud-k8s/gcp.tf`.
- **Rug-pull detection with teeth**: every MCP server's tool manifest (launch
  identity + tool surface) is canonically hashed at scan time
  (`attestral/manifest.py`), pinned into the compiled policy as
  `manifest_sha256`, and re-checked by `drift` - a mismatch is DRF-005
  (critical): the tool that runs is not the tool that was reviewed.
- **Agent→cloud reachability edges**: cloud provider credentials in a tool
  server's env are detected (`_has_cloud_credentials`), flagged as ATL-112
  (high), and recorded as a `tool_access` edge from the server to the cloud
  boundary - the crossing becomes part of the attested model hash.
- **Memory/context poisoning (OWASP ASI06)**: standing agent-instruction files
  (CLAUDE.md, `.cursorrules`, AGENTS.md, `.windsurfrules`, Copilot
  instructions) are ingested as `agent_instruction` components. World-writable
  instruction files fire ATL-113 (high, deterministic); the file content is
  scored for embedded injection by the ML layer. Fixture:
  `examples/memory-poisoning/`.

## [0.7.0] - 2026-07-12

### Added
- **Agentic depth wave** (OWASP ASI 2026-anchored): auto-approved tool execution
  (ATL-108), unauthenticated remote MCP servers (ATL-109), credentials in argv
  (ATL-110), broad host mounts into MCP containers (ATL-111).
- **Fleet-level combination rules** via the new capability model and
  `model_capability_combo` matcher: lethal-trifecta exfiltration chain (ATL-202)
  and shell + network reach (ATL-203) - findings only a system model can produce.
- **Cross-server tool shadowing detection** (SAFE-MCP SAF-T1301-anchored,
  fixture `examples/tool-shadowing/`): tool-name collisions (ATL-204),
  cross-server steering in tool descriptions (ATL-205), and server-identity
  conflicts across config scopes (ATL-206) - all model-level; findings now
  carry per-instance detail (which tool, which servers, which sources).
- `attestral scan --local`: audits MCP servers already installed on the machine
  (Claude Code - user scope, project `.mcp.json`, and the current project's
  local scope nested in `~/.claude.json` - plus Claude Desktop, Cursor,
  VS Code, Windsurf). Prints an inventory of the reviewed agent tool surface
  (server, transport, capability classes, source) and per-source server
  counts, so a clean scan shows its work and an empty config is
  distinguishable from a broken one.
- `attestral init`: one-command scaffold of CI workflow, pre-commit config, and
  waivers file. Pre-commit hooks (`attestral`, `attestral-local`).
- Terminal-first output: colour-coded review printed to the terminal, nothing
  written to disk unless `-o`/`--format` is passed.
- Docs-sync gate: README diagrams, CLI docs, and this changelog are enforced by
  the test suite.
- OWASP ASI:2026 framework references across the agentic rule pack (66 rules total).

## [0.6.0] - 2026-07-11

### Added
- ML layer tier 3: fine-tunable DeBERTa prompt-injection classifier
  (`attestral[ml]`), joining the zero-dep heuristic and ONNX tiers; all tiers
  emit byte-identical findings.
- Rule pack grown to 57 rules: AWS extras plus new Azure, GCP, and Kubernetes
  packs (CIS-grounded).
- `training/`: fine-tune and threshold-calibration recipe for the ML layer.

## [0.5.0] - 2026-07-11

### Added
- Rule pack grown to 26 rules (CIS AWS + OWASP LLM Top 10 + MCP supply-chain
  research: auto-install, mutable tags, outbound fetch/browser tools).
- Judge testability: deterministic judge harness; live judge test skips
  without an API key.
- Diagrammatic docs: pipeline and command-loop Mermaid diagrams.

## [0.4.0] - 2026-07-11

### Added
- LLM-as-judge verifier layer (`--judge`): panel voting, verdicts recorded in
  the evidence chain, `--judge-suppress` auto-waives confident false positives
  on the record.

## [0.3.0] - 2026-07-11

### Added
- Baseline + waivers: documented, expiring exceptions
  (`attestral-waivers.yaml`); waived findings stay in the evidence chain and
  become SARIF suppressions.

## [0.2.0] - 2026-07-11

### Added
- SARIF 2.1.0 output for GitHub Code Scanning (`--format sarif`).

## [0.1.0] - 2026-07-11

### Added
- First release: system model (components, edges, trust boundaries), Terraform
  + MCP ingestion, 10-rule deterministic pack, SHA-256 evidence chain with
  offline `verify`, `compile` to default-deny mcp-guard policy, `drift`
  detection against runtime telemetry, CLI with CI gate (`--fail-on`).
