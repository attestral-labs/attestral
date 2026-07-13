# Attestral

[![PyPI](https://img.shields.io/pypi/v/attestral)](https://pypi.org/project/attestral/)
[![CI](https://github.com/attestral-labs/attestral/actions/workflows/ci.yml/badge.svg)](https://github.com/attestral-labs/attestral/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/attestral)](https://pypi.org/project/attestral/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

**The security scanner for AI agents and MCP servers.**

<p align="center">
  <img src="examples/vulnerable-agent/demo.gif"
       alt="attestral scan flagging an insecure MCP agent config in seconds"
       width="820">
</p>

<!-- RESEARCH POST: "We scanned N popular MCP servers" — link TBD -->

Attestral reviews the security *design* of AI agents and MCP servers. It reads your MCP/agent configs, system prompts, and tool descriptions, builds one system model, and reviews the agentic surfaces most scanners never look at, checking them against a deterministic rule pack, with an optional local ML layer for prompt injection, LLM reasoning, and an LLM-as-judge. And it models your cloud (Terraform) and Kubernetes *alongside* the agent, so it can see the trust boundary between the agent and the infrastructure it can reach, not just each in isolation. Every finding lands in a **tamper-evident SHA-256 evidence chain** you can hand to reviewers, auditors, and customers.

```bash
pip install attestral
attestral scan ./my-project
```

## Scan the MCP servers you've already installed

No repo needed. Audit the MCP servers your agent tools are already wired to:

```sh
attestral scan --local
```

Discovers and scans configs from Claude Code (user scope, project `.mcp.json`, and the current project's local scope inside `~/.claude.json`), Claude Desktop, Cursor, VS Code, and Windsurf. It reports which sources were found vs absent and how many servers each contributed, prints an inventory of the agent tool surface it reviewed, and runs everything through the same rule pipeline as a repo scan.

## Get started in one command

```sh
attestral init      # scaffold CI, pre-commit, and a waivers file into this repo
attestral scan .    # review the current project - prints straight to your terminal
```

`attestral init` writes three onboarding files, and **never overwrites anything that already exists** (existing files are skipped and reported):

| File | What it does |
|---|---|
| `.github/workflows/attestral.yml` | Gates every PR in CI and uploads findings to the Security tab. |
| `.pre-commit-config.yaml` | Runs attestral on every commit (see [pre-commit](#run-attestral-on-every-commit)). |
| `attestral-waivers.yaml` | Starter for documented, expiring exceptions. |

### Terminal-first output

`attestral scan` prints a colour-coded, severity-grouped review straight to your terminal and **writes nothing to disk by default** - no more `attestral-report.*` files littering your repo. Ask for report files explicitly, with `-o` (a file stem) or `--format`:

```sh
attestral scan .                          # print only - nothing is written
attestral scan . -o review                # write review.md + review.json
attestral scan . --format sarif -o out    # write out.sarif for GitHub Code Scanning
attestral scan . --quiet --fail-on high   # CI: just the summary + gate line, exit 1 on high+
```

`--quiet` drops the per-finding detail and prints only the summary and gate (nothing at all on a clean scan). Colour is emitted only to an interactive terminal and is suppressed under `NO_COLOR` or when the output is piped, so CI logs and pipes stay plain.

### Explain any rule

```sh
attestral explain ATL-103    # title, severity, description, fix, and framework refs
```

Every finding in the terminal output carries a `run: attestral explain <RULE_ID>` pointer, so the reasoning and the fix are one command away. Rule ids are matched case-insensitively.

## What it catches (85-rule pack)

| Area | Examples |
|---|---|
| **Agentic / MCP** (OWASP LLM Top 10, MCP research) | shell-capable servers, broad filesystem roots, non-TLS transport, secrets in env, auto-installed packages (supply chain), mutable `@latest` tags (rug-pull), outbound-fetch/browser tools |
| **Memory / context poisoning** (OWASP ASI06, agent-security SoK) | world-writable agent-instruction files (CLAUDE.md, `.cursorrules`, AGENTS.md) that anyone can rewrite to steer every future run; persistent memory / vector stores as memory-poisoning targets |
| **ML layer** (`attestral[ml]`) | prompt-injection / jailbreak text in MCP tool & server descriptions, system prompts, and agent-instruction files |
| **AWS** (CIS-grounded) | public S3/RDS/Redshift, `0.0.0.0/0` security groups, wildcard IAM, unencrypted RDS/EBS/EFS/Neptune, disabled backups, KMS rotation off, public EC2/EKS, CloudTrail gaps, mutable ECR tags, plaintext ELB listeners |
| **Azure** (CIS-grounded) | public blob access, non-HTTPS storage, storage TLS < 1.2 and no infrastructure encryption, public SQL, wildcard NSG rules, Key Vault purge protection off / public network access, Postgres/MySQL SSL not enforced, Postgres flexible server public access, SQL database TDE off, App Service not HTTPS-only, VM password auth, AKS local accounts enabled |
| **GCP** (CIS-grounded) | `0.0.0.0/0` firewall rules, public Cloud SQL, SQL without SSL, public bucket IAM (`allUsers`), bucket uniform-access off, KMS keys without rotation, Compute cloud-platform scope / IP forwarding / non-Shielded VMs, GKE legacy ABAC, non-private nodes, non-Shielded nodes, client-cert auth |
| **Kubernetes** (CIS K8s) | privileged containers, privilege escalation, dangerous capabilities, run-as-root, host network/PID, hostPath mounts, missing resource limits, mutable image tags |
| **Cross-cutting** (fleet-level, only visible in a system model) | lethal-trifecta capability combos (private data + egress), shell + network reach, cross-server tool shadowing (tool-name collisions, steering descriptions, server-identity conflicts), agent runtime and cloud sharing no declared boundary controls |

Every finding maps to NIST 800-53, ASVS, SOC 2, CIS (AWS/Azure/GCP/K8s), OWASP LLM/Agentic, and MITRE ATLAS references. The agentic checks are additionally mapped to the attack/risk taxonomy of the agent-security SoK (Kim et al. 2026) in [docs/agentic-threat-model.md](docs/agentic-threat-model.md).

## How a scan works (the pipeline)

```mermaid
flowchart TB
    subgraph ING["1 · Ingest"]
        TF["Terraform (.tf)"] --> M
        K8S["Kubernetes<br/>manifests (.yaml)"] --> M
        MCP["MCP configs<br/>(mcp.json)"] --> M
        SP["System prompts, agent instructions<br/>(CLAUDE.md/.cursorrules) + tool descriptions"] --> M
        LC["Installed agent configs<br/>(scan --local)"] --> M
        M["SystemModel<br/>components · edges · trust boundaries"]
    end
    M --> L1
    subgraph REV["2 · Review (layered, each finding tagged by origin)"]
        L1["<b>L1 Deterministic rules</b><br/>85 typed matchers · fail-closed<br/>origin: deterministic"]
        L2["<b>L2 ML classifier</b> (optional)<br/>DeBERTa prompt-injection on agentic surfaces<br/>origin: ml"]
        L3["<b>L3 LLM</b> (optional)<br/>elicitation + LLM-as-judge verifier<br/>origin: llm"]
        L1 --> L2 --> L3
    end
    REV --> W["Waivers<br/>documented, expiring exceptions"]
    W --> EV["3 · Evidence<br/>SHA-256 hash chain · verify offline"]
    EV --> OUT["Output: Terminal (default, writes nothing) · Markdown · JSON · <b>SARIF</b> (Code Scanning)"]
    style L1 fill:#0a7d3611,stroke:#0a7d36
    style L3 fill:#96222E11,stroke:#96222E
```

| Layer | What it does | Reproducible? | Cost |
|---|---|---|---|
| **L1 Deterministic** | 85 typed matchers over the model, fail-closed (unknown matcher never matches) | Yes, fully | Free, offline |
| **L2 ML** (optional) | Scores agentic text surfaces (MCP tool/server descriptions, system prompts) for prompt injection / jailbreaks. Three tiers: zero-dep heuristic (default), ONNX (`attestral[onnx]`, model-grade, no torch), or DeBERTa (`attestral[ml]`) | Pinned model + revision | Free, offline after first cache |
| **L3 LLM** (optional) | Elicits novel design threats, and a judge cross-examines findings to cut false positives | Verdicts recorded in the chain | Your API key |

Every finding carries its `origin`, so the deterministic core is never silently mixed with model reasoning. That separation is what makes the review audit-grade.

## The sophistication layers (optional)

```bash
# ML prompt-injection scan of agentic text surfaces (MCP tool/server descriptions and
# system-prompt files). Hits are tagged origin: ml and flow into the same evidence chain.
# Three tiers, chosen with --ml-engine (or ATTESTRAL_ML_ENGINE); default is auto:
#   heuristic  zero-dependency, instant, ships in core  -> attestral scan --ml (no extra install)
#   onnx       model-grade DeBERTa via onnxruntime, no torch, ~276 MB   <- recommended
#   deberta    heaviest, fine-tunable, pulls torch (~700 MB+)
# `auto` precedence: onnx -> deberta -> heuristic. A missing extra is never an error.
attestral scan ./my-project --ml                          # zero-install heuristic tier
pip install "attestral[onnx]"                             # add the light, accurate ONNX tier
attestral scan ./my-project --ml --ml-engine onnx         # weights auto-download once, offline after
# custom or air-gapped model? run scripts/export_onnx.py, then set ATTESTRAL_ML_MODEL=/path
attestral scan ./my-project --ml --ml-threshold 0.7       # tune sensitivity

# LLM threat elicitation on top of the deterministic layer
export ANTHROPIC_API_KEY=...
attestral scan ./my-project --llm

# LLM-as-judge: cross-examine findings to cut false positives.
# Verdicts (confirmed / false_positive / needs_review) are recorded in the chain.
export ATTESTRAL_JUDGE_API_KEY=...                 # or reuse ANTHROPIC_API_KEY
attestral scan . --judge --judge-panel 3           # 3 judges vote per finding
attestral scan . --judge --judge-suppress          # auto-waive confident false positives, on the record
```

The judge never deletes a finding. A confident `false_positive` becomes a machine-generated waiver carrying the judge's reasoning: suppressed from the gate, but kept on the record.

### Tuning / training the ML layer

The ML layer ships pointed at a DeBERTa classifier already fine-tuned for prompt injection, so **start zero-shot** (`--ml`, no training). If you need to adapt it to your own surfaces, climb three tiers - use as-is, calibrate the `--ml-threshold` on your labeled data, then fine-tune only if a gap remains. A runnable recipe (fine-tune + threshold-calibration scripts, data format, and where to source training data) lives in [`training/`](training/README.md).

## Baseline and waivers

Real repos start with findings. A waiver accepts a known risk and keeps the gate green without hiding anything: the waived finding stays in the evidence chain with its justification, and becomes a SARIF suppression (GitHub shows it dismissed, not open).

```yaml
# attestral-waivers.yaml  (auto-discovered at the scan root)
waivers:
  - rule: ATL-005
    component: aws_db_instance.app     # or "*" for every component
    reason: Encryption enforced at the storage layer; tracked in SEC-1234.
    expires: 2026-12-31                # optional
```

Fail-safe: a waiver with no `reason` is ignored, and an expired waiver stops suppressing. A finding can only be silenced by a current, justified exception.

## Beyond findings: prove it, enforce it, verify it

A scanner stops at a list of findings. Attestral turns the reviewed design into a tamper-evident record and a runtime policy: the depth that makes the review audit-grade, and the reason it can't be trivially cloned. Attest the design, prove the record has not been altered, compile it into a default-deny runtime policy, and detect when what runs diverges from what was reviewed. The whole loop runs offline, on a laptop, free.

### The loop in one picture

```mermaid
flowchart LR
    A["attestral scan<br/><b>attest</b>"] --> B["attestral verify<br/><b>prove</b>"]
    A --> C["attestral compile<br/><b>enforce</b>"]
    C --> D["attestral drift<br/><b>detect</b>"]
    D -->|"design changed?<br/>re-attest"| A
    style A fill:#96222E,color:#fff
    style B fill:#1F6A4A,color:#fff
```

### The four commands

```mermaid
flowchart LR
    subgraph scan["attestral scan"]
        s1["Terraform + MCP"] --> s2["findings + evidence chain<br/>md / json / sarif"]
    end
    subgraph verify["attestral verify"]
        v1["report.json"] --> v2["VALID / INVALID<br/>(offline)"]
    end
    subgraph compile["attestral compile"]
        c1["attested model"] --> c2["default-deny policy<br/>tool manifest hashes pinned,<br/>bound to chain head"]
    end
    subgraph drift["attestral drift"]
        d1["policy + telemetry"] --> d2["drift findings<br/>incl. manifest rug-pulls (DRF-005)"]
    end
```

```bash
# SCAN: review a project (Terraform + MCP configs discovered automatically)
attestral scan ./my-project --format both          # md + json
attestral scan . --fail-on high                    # CI gate: exit 1 on high/critical
attestral scan . --format sarif -o attestral       # SARIF -> GitHub Security tab + PR annotations

# VERIFY: prove a report has not been altered (no network, no server)
attestral verify review.json

# COMPILE: turn the attested design into a default-deny mcp-guard policy
attestral compile ./my-project -o policy.yaml

# DRIFT: diff runtime telemetry against the attested design
attestral drift policy.yaml events.jsonl --fail-on-drift
```

### Install and run the whole loop (60 seconds)

```bash
pip install attestral

attestral scan examples/demo-project -o review        # attest  -> review.md + review.json
attestral verify review.json                          # prove   -> chain VALID
attestral compile examples/demo-project -o policy.yaml # enforce -> default-deny policy
attestral drift policy.yaml examples/demo-project/runtime-events.jsonl --fail-on-drift  # detect
```

## Real-world benchmark

Run on [TerraGoat](https://github.com/bridgecrewio/terragoat) (Bridgecrew's deliberately-vulnerable Terraform), same repo, growing rule packs:

| | TerraGoat AWS | TerraGoat Azure | TerraGoat GCP |
|---|---|---|---|
| v0.4.0 (10 rules) | 3 | - | - |
| v0.5.0 (26 rules) | 6 | - | - |
| v0.6.0 (57 rules) | **7** | **2** | **3** |

v0.6.0 extends coverage from AWS-only to AWS + Azure + GCP + Kubernetes (12 findings across the three TerraGoat clouds). The pipeline (ingest, evidence chain, tamper detection, gate, SARIF) is verified on real code; the rule pack keeps growing to raise coverage.

## Use it in CI

```yaml
# .github/workflows/attestral.yml
name: attestral
on: [pull_request]
permissions:
  contents: read
  security-events: write        # to upload to the Security tab
jobs:
  design-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-python@v6
        with: { python-version: "3.12" }
      - run: pip install "attestral[terraform]"
      - run: attestral scan . --format sarif -o attestral
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: attestral.sarif }
      - run: attestral scan . --fail-on high      # hard gate (auto-uses attestral-waivers.yaml)
```

Ready-made workflows live in `examples/github-actions/`.

## Run attestral on every commit

```sh
pip install pre-commit
```

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/attestral-labs/attestral
    rev: v0.6.0
    hooks:
      - id: attestral        # gate infra/agent config in this repo
      - id: attestral-local  # optional: audit installed MCP servers
```

Then `pre-commit install`. See `examples/pre-commit/` for details.

## Writing custom rules

Rules are YAML with structured matchers. No `eval` anywhere, and an unknown matcher fails closed (never matches).

```yaml
rules:
  - id: ORG-001
    title: Internal load balancer missing auth attribute
    severity: high
    target: aws_lb                     # component type prefix, or "model"
    match: { attr_missing: auth }
    description: ...
    recommendation: ...
    frameworks: ["NIST AC-3", "SOC2 CC6.1"]
```

```bash
python -c "from attestral.rules import RuleEngine; RuleEngine(['org_rules.yaml'])"
```

## Development

```bash
pip install -e ".[dev,terraform,llm]"   # add ,ml for the DeBERTa layer (pulls torch)
pytest -q                 # offline suite; the live judge test skips without a key
ruff check attestral tests
```

To run the live judge test, set `ATTESTRAL_JUDGE_API_KEY` (or `ANTHROPIC_API_KEY`) and re-run `pytest -q`.

### How a change ships

```mermaid
flowchart LR
    subgraph inner["inner loop (local)"]
        E["edit code / rules / ingesters"] --> T["pytest -q · ruff"]
        T --> S["attestral scan examples/*<br/>(eyeball real findings)"]
        S --> E
    end
    S --> PR["pull request"]
    PR --> CI["CI: lint + tests on 3.10 / 3.12<br/>+ docs-sync gate"]
    CI --> REV["CODEOWNERS review · CLA signed"]
    REV --> MAIN["main (protected: no force push,<br/>required checks)"]
    MAIN --> TAG["tag vX.Y.Z + CHANGELOG entry"]
    TAG --> PUB["publish.yml → PyPI<br/>(Trusted Publishing)"]
```

The **docs-sync gate** (`tests/test_docs_sync.py`) keeps this README honest: it
fails when a pipeline module exists that no diagram shows, when a CLI command
is undocumented, or when the package version has no `CHANGELOG.md` entry. If
you add a stage, draw it — the suite won't pass until you do.

## License

Apache 2.0.
