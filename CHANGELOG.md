# Changelog

All notable changes to Attestral. Format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [SemVer](https://semver.org/). This file is enforced: the suite
fails if the package version has no entry here (`tests/test_docs_sync.py`).

## [Unreleased]

### Added
- **Agent-security SoK mapping** (Kim et al., _The Attack and Defense Landscape
  of Agentic AI_, arXiv:2603.11088, 2026): the agentic rule pack is mapped to
  the survey's V1–V6 attack vectors and R1–R7 risk taxonomy in
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
  and shell + network reach (ATL-203) — findings only a system model can produce.
- **Cross-server tool shadowing detection** (SAFE-MCP SAF-T1301-anchored,
  fixture `examples/tool-shadowing/`): tool-name collisions (ATL-204),
  cross-server steering in tool descriptions (ATL-205), and server-identity
  conflicts across config scopes (ATL-206) — all model-level; findings now
  carry per-instance detail (which tool, which servers, which sources).
- `attestral scan --local`: audits MCP servers already installed on the machine
  (Claude Code — user scope, project `.mcp.json`, and the current project's
  local scope nested in `~/.claude.json` — plus Claude Desktop, Cursor,
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
