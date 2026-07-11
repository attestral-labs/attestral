# Attestral

[![PyPI](https://img.shields.io/pypi/v/attestral)](https://pypi.org/project/attestral/)
[![CI](https://github.com/attestral-labs/attestral/actions/workflows/ci.yml/badge.svg)](https://github.com/attestral-labs/attestral/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/attestral)](https://pypi.org/project/attestral/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**Continuous, audit-ready security design review for cloud and agentic systems.**

Attestral ingests your infrastructure-as-code and agent/MCP configurations, builds a unified system model, runs a deterministic rule pack (plus optional LLM threat elicitation), and produces a design review with a **tamper-evident evidence chain** you can hand to reviewers, auditors, and customers.

```
pip install attestral
attestral scan ./my-project
```

## Why

- Legacy threat modeling platforms are questionnaire-driven, consultant-heavy, and priced for the Fortune 500. In practice most teams do this work in a spreadsheet.
- The fastest-growing attack surface (AI agents, MCP servers, tool permissions) is the one legacy tools understand least.
- Review output is only worth what you can prove. Every Attestral run emits a SHA-256 hash chain over its findings, and altering any past entry invalidates the chain head.

## What it does today (v0.4)

| Layer | Status |
|---|---|
| Terraform ingestion (design-level) | ✅ dependency-free scanner |
| MCP server config ingestion | ✅ `mcp.json` / `claude_desktop_config.json` |
| Deterministic rule pack | ✅ 10 rules: cloud misconfig + agentic tool risk |
| Framework mapping | ✅ NIST 800-53, ASVS, SOC 2, OWASP Agentic refs per finding |
| Evidence chain + verification | ✅ `attestral verify report.json` |
| SARIF output for GitHub Code Scanning | ✅ `--format sarif` → Security tab + PR annotations |
| Fail-closed CI gate | ✅ `--fail-on high` |
| Baseline + waivers | ✅ documented, expiring exceptions kept in the evidence chain |
| LLM threat elicitation | ✅ optional, `--llm` + `ANTHROPIC_API_KEY`, findings tagged separately |
| LLM-as-judge verifier | ✅ optional, `--judge` cross-examines findings; panel voting; verdicts in the chain |
| Design→policy compiler (`attestral compile`) | ✅ mcp-guard default-deny policy, bound to the review chain head |
| Design-runtime drift detection (`attestral drift`) | ✅ JSONL telemetry diffed against the attested design |
| PR design-diff (GitHub App) | 🔜 roadmap |
| IriusRisk/ThreatModeler import | 🔜 roadmap |

## Usage

```bash
# Scan a project (Terraform + MCP configs discovered automatically)
attestral scan ./my-project

# Markdown + JSON evidence report
attestral scan ./my-project -o review --format both

# CI gate: fail the pipeline on high/critical design findings
attestral scan . --fail-on high

# Emit SARIF for GitHub Code Scanning (Security tab + inline PR annotations)
attestral scan . --format sarif -o attestral
# then upload attestral.sarif via github/codeql-action/upload-sarif@v3
# (ready-made workflow: examples/github-actions/code-scanning.yml)

# Accept a known risk without disabling the gate: add a documented waiver.
# A waived finding is suppressed from --fail-on but stays in the evidence
# chain with its justification. See examples/attestral-waivers.example.yaml
attestral scan . --fail-on high   # auto-discovers attestral-waivers.yaml

# Add LLM design-review reasoning on top of the deterministic layer
export ANTHROPIC_API_KEY=...
attestral scan ./my-project --llm

# Cross-examine findings with an LLM judge (cuts false positives).
# Verdicts (confirmed/false_positive/needs_review) are recorded in the chain.
export ATTESTRAL_JUDGE_API_KEY=...          # or reuse ANTHROPIC_API_KEY
attestral scan ./my-project --judge --judge-panel 3
attestral scan ./my-project --judge --judge-suppress   # auto-waive confident false positives, on the record

# Prove a report hasn't been altered
attestral verify review.json

# Close the loop: compile the attested design into a runtime policy...
attestral compile ./my-project -o policy.yaml
# ...and diff runtime telemetry (mcp-guard JSONL) against it
attestral drift policy.yaml events.jsonl --fail-on-drift
```

Try it on the included demo:

```bash
attestral scan examples/demo-project
```

## Architecture

1. **Ingest** → unified `SystemModel` (components, edges, trust boundaries) from Terraform and MCP configs.
2. **Deterministic layer** → typed matchers in YAML rules (`attestral/rules/core_rules.yaml`). No `eval`, unknown matchers fail closed.
3. **LLM layer (optional)** → design-level threat elicitation over the model JSON; findings tagged `origin: llm`, never silently mixed with deterministic results.
4. **Judge layer (optional)** → an LLM cross-examines each finding for false positives; a panel of judges can vote. Verdicts are recorded on the finding and in the chain. The judge never deletes a finding: a confident false positive becomes a machine-generated waiver with the judge's reasoning, kept on the record.
5. **Evidence layer** → hash-chained findings, markdown/JSON export, offline verification.

## Writing custom rules

```yaml
rules:
 - id: ORG-001
 title: Internal service exposed without auth attribute
 severity: high
 target: aws_lb
 match: { attr_missing: auth }
 description: ...
 recommendation: ...
 frameworks: ["NIST AC-3"]
```

```bash
attestral scan . # core pack
python -c "from attestral.rules import RuleEngine; RuleEngine(['org_rules.yaml'])"
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check attestral tests
```

## License

Apache 2.0
