# Contributing to Attestral

Thanks for helping make agentic infrastructure safer. Contributions of every
size are welcome: rules, ingesters, fixtures, docs, bug reports.

## Scope

This repo is the complete open-source core: model, ingesters, rules, evidence
chain, compiler, drift detection, telemetry, Action. Hosted/team features are
developed elsewhere and are out of scope here.

## Ground rules

- Open an issue before large changes; small fixes can go straight to PR.
- Every PR needs tests. `.venv/bin/pytest -q` and
  `.venv/bin/ruff check attestral/ tests/` must pass. Run pytest from the repo
  root; `testpaths` is pinned to `tests/` on purpose.
- New detection rules go in YAML with structured matchers - no executable logic
  in rule files, ever. Unknown matchers fail closed by design.

## Sign your work (DCO)

Attestral uses the [Developer Certificate of Origin](https://developercertificate.org/).
Every commit must carry a `Signed-off-by` line certifying you have the right to
contribute the code under the project's Apache 2.0 license:

```
git commit -s
```

Pull requests with unsigned commits will be asked to rebase. This is provenance
paperwork, not a copyright assignment: you keep your copyright.

## Development setup

```bash
git clone https://github.com/attestral-labs/attestral && cd attestral
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,terraform]"
.venv/bin/pytest -q
.venv/bin/ruff check attestral/ tests/
```

## Contributing a rule (the most common contribution)

Rules are pure YAML data; no code change is needed for a standard check.

- Agentic and cross-boundary rules live in `attestral/rules/core_rules.yaml`;
  cloud rules live in the per-provider packs (`aws_pack.yaml`, `azure_pack.yaml`,
  `gcp_pack.yaml`, `k8s_pack.yaml`).
- ID bands: `0xx` AWS, `1xx` MCP/agentic, `2xx` cross-boundary, `3xx` Azure,
  `4xx` GCP, `5xx` Kubernetes. Pick the next free id in the right band.
- Every rule needs: a `target` matching a real component type an ingester emits,
  a matcher from the fail-closed set in `rules/engine.py`, real framework
  citations (OWASP-AgSec/CIS/NIST - they are audit artifacts, not decoration),
  a fixture under `examples/` that triggers it, and a test asserting it fires.
- Bias toward precision. A rule that false-positives gets the whole scanner
  muted; a rule nobody would act on is worse than no rule.

## What will not be merged

- `eval`, string execution, or matchers that fail open.
- Heavy imports at module top level (`transformers`, `torch`, `anthropic` stay
  lazy inside functions; a missing optional extra must never be an error).
- Scan output that writes files without `-o`/`--format` (terminal-first).
- Changes that weaken the evidence chain's tamper-evidence.

## Reporting security issues

Do not open a public issue for a vulnerability in Attestral itself. Email the
maintainer (see the repository profile) with details; you will get a response
within a few days.
