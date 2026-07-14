# Changelog

All notable changes to Attestral. Format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [SemVer](https://semver.org/). This file is enforced: the suite
fails if the package version has no entry here (`tests/test_docs_sync.py`).

## [Unreleased]

### Added
- **Agentic AI Risk Score (`attestral scan --aivss`).** New `attestral/aivss.py`
  scores agentic findings with an OWASP AIVSS Agentic AI Risk Score (AARS) and
  ranks them, mapping each to an OWASP Agentic (ASI) / LLM Top-10 category. AARS
  measures agentic amplification, a different axis from CVSS severity, so a
  compositional fleet risk like the lethal trifecta outranks a high-CVSS but
  contained one. Opt-in, off by default. Tests: `tests/test_aivss.py`.

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
