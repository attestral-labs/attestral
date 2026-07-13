# Attestral - operating guide

Continuous, audit-ready security **design review** for **AI agents / MCP servers** and the cloud they can reach. Not a linter of code; a reviewer of *architecture*. Python 3.10+, deps are just `click` + `pyyaml` (everything heavier is an optional extra).

## North star - where we compete (read before adding scope)

Do **not** chase Checkov on rule count. They have 1000+ policies and a funded team; that race is unwinnable and off-strategy. We win on a barbell:

1. **Agentic security = our identity. Be #1, uncontested.** MCP, prompt injection, tool poisoning, excessive agency, agent supply chain, OWASP-LLM/Agentic Top 10, MITRE ATLAS. Depth here is the moat. When in doubt, invest here.
2. **Architecture Checkov structurally can't match.** We build a *system model* (components + edges + trust boundaries), so we reason about agent↔cloud reachability, secrets crossing a boundary, cross-resource relationships, the evidence chain, and compile→drift. Make these cross-cutting findings the headline. Not copyable by adding rules.
3. **Cloud rules: parity on what matters, not volume.** ~150 high-signal CIS/essential checks, not the long tail. "Good enough nobody needs a second tool," never an arms race.

One-liner: *"The security scanner built for the agentic era - and it covers your cloud as well as the dedicated tools."*

## Pipeline (how a scan flows)

`build_model(path)` → `SystemModel` → layers append `Finding`s → waivers → report + evidence chain.

- **Ingest** (`attestral/ingest/`): `terraform.py`, `kubernetes.py`, `mcp.py`, `prompts.py`. `scan.py::build_model` runs all four and seeds trust boundaries (`cloud`, `cluster`, `agent_runtime`). `local_config.py` discovers installed MCP configs (Claude Desktop/Cursor/VS Code/Windsurf) for `scan --local`.
- **Model** (`model.py`): `Component`(id/type/name/source/attributes/trust_boundary), `Edge`, `TrustBoundary`, `Finding`, `Severity` (critical=4…info=0). This is the shared vocabulary - everything keys off `component.type` and `component.attr(...)`.
- **Rules** (`rules/engine.py` + `rules/core_rules.yaml`): deterministic, `origin="deterministic"`. Always runs.
- **ML** (`ml.py`, `--ml`): prompt-injection scoring on *language* surfaces (MCP tool/server descriptions, system-prompt files). `origin="ml"`. Tiered, off by default.
- **LLM** (`llm.py`, `--llm`) and **Judge** (`judge.py`, `--judge`): elicitation + LLM-as-judge cross-examination. Need `ANTHROPIC_API_KEY`.
- **Waivers** (`waivers.py`): documented, expiring exceptions; a waived finding stays in the chain (never hidden), becomes a SARIF suppression.
- **Output**: `report_terminal.py` (default, terminal-first), `evidence.py` (SHA-256 chain + markdown), `sarif.py`. **Terminal-first: nothing is written to disk unless `-o`/`--format` is passed.**
- **Runtime loop**: `compile.py` (`attestral compile`) turns the attested design into an mcp-guard policy (default-deny); `drift.py` (`attestral drift`) diffs runtime events against it. "Attested design becomes runtime policy" is a moat neither Checkov nor a pure-LLM tool has - grow it.

## Commands

```bash
.venv/bin/pytest -q            # 107 pass / 2 skip. testpaths is pinned to tests/ in pyproject.
.venv/bin/ruff check attestral/
.venv/bin/attestral scan <path>            # core scan (terminal only)
.venv/bin/attestral scan <path> --ml --judge --fail-on high   # full pipeline + CI gate
.venv/bin/attestral scan --local           # audit MCP configs installed on this machine
.venv/bin/attestral explain ATL-103        # inspect any rule
```

Never run bare `pytest` from repo root without the pinned `testpaths` - `research/` holds vendored third-party MCP repos whose tests would swamp collection. The pin handles it; don't undo it.

## Adding a rule (the most common change)

Rules are pure data in `rules/core_rules.yaml`. No code change needed for a standard check.

**ID namespaces:** `0xx` AWS · `1xx` MCP/agentic · `2xx` cross-boundary (`target: model`) · `3xx` Azure · `4xx` GCP · `5xx` Kubernetes. Pick the next free id in the right band.

**Shape:**
```yaml
- id: ATL-1NN
  title: <imperative problem statement>
  severity: critical|high|medium|low|info
  target: <component.type prefix, e.g. mcp_server, aws_s3_bucket, k8s_container>
  match: { <matcher>: { <attr>: <value> } }
  description: <why it's a risk, in one sentence>
  recommendation: <the concrete fix>
  frameworks: ["NIST AC-6", "OWASP-AgSec TOOL-1", "CIS AWS 2.3.1"]   # cite real controls
```

**Matchers** (in `engine.py::_matches`, all fail **closed** - an unknown matcher never fires):
`attr_equals` · `attr_in` (value in list) · `attr_missing` · `attr_starts_with` · `attr_contains` (substring) · `attr_list_contains` · `attr_list_any_of` (exact token or `v/`-prefixed path; deliberately NOT bare substring) · `attr_any_contains` · and model-level `model_has_both: [typeA, typeB]` for cross-boundary rules.

**Rules for rules:**
- The `target` must match a real `component.type` an ingester emits. Attributes prefixed `_` (e.g. `_cidr_blocks`, `_env_has_secrets`) are ingester-derived; check the ingester before matching them.
- **Every new rule needs a test** with a fixture that triggers it - mirror `tests/test_multicloud_rules.py` (build a model from an `examples/` fixture, assert the id fires). Add the fixture under `examples/`.
- Agentic rules cite `OWASP-AgSec …`; cloud rules cite CIS/NIST/SOC2. Keep framework refs accurate - they're an audit artifact, not decoration.
- Language-based risk (injection, poisoning) is *not* a rule - it lives in `ml.py`, because the risk is in the words, not a flag.

## Design invariants - do not break

- **No `eval`, no string execution.** Every matcher is a named, typed check. Fail-closed is a security property, keep it.
- **ML tiers emit byte-identical findings.** heuristic (zero-dep) → onnx (`attestral[onnx]`, no torch) → deberta (`attestral[ml]`). `--ml` always works with no install via the heuristic tier and degrades gracefully. Heavy deps (`transformers`, `torch`, `anthropic`) are **imported lazily inside functions**, never at module top level - a missing extra is never an error.
- **Evidence chain is tamper-evident.** Don't reorder/mutate findings after `audit_chain`. `verify_chain` must stay able to detect any alteration. Waived ≠ deleted.
- **Terminal-first.** Don't make the scanner write files unless the user asked (`-o`/`--format`).
- **Docs stay in sync - enforced, not promised.** `tests/test_docs_sync.py` gates: every pipeline module must appear in a README mermaid diagram (via its `DIAGRAM_KEYWORDS` map), every CLI command must have an `attestral <cmd>` usage example in the README, and the current `__version__` must have a `CHANGELOG.md` entry. When you add a module/command/release: draw it, document it, log it - the suite fails until you do.
- Full suite must stay green + `ruff` clean before any commit.

## Parallel-agent discipline (avoid race/merge conflicts)

**Hot files** - many tasks want to touch these; serialize them:
`rules/core_rules.yaml`, `cli.py`, `pyproject.toml`, `README.md`.

- **A rule-expansion wave = one rules-owner agent, OR git-worktree isolation per agent, never N agents editing `core_rules.yaml` at once.** That single shared YAML is the classic race; partitioning by file doesn't help when every agent wants the same file.
- Non-overlapping work (a new ingester + its tests + its fixture) → give each agent a disjoint file set and one reconciliation owner for the hot seams.
- When agents *must* touch overlapping code, isolate each in its own git worktree and merge deliberately, or drive the fan-out as a deterministic Workflow (worktree isolation + explicit merge/verify stages) rather than ad-hoc parallel agents.

## Repo map

`attestral/` package · `tests/` suite · `examples/` rule fixtures + demos · `research/` vendored MCP repos for the ecosystem scan (NOT part of the suite, untracked) · `scripts/` (incl. `export_onnx.py`) · `website/` marketing site · `training/` ML fine-tune assets.
