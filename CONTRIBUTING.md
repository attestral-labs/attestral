# Contributing to Attestral

Thanks for considering a contribution.

## Ground rules
- Open an issue before large changes; small fixes can go straight to PR.
- Every PR needs tests. `pytest -q` and `ruff check attestral tests` must pass.
- New detection rules go in YAML with structured matchers (see docs) - no
 executable logic in rule files, ever. Unknown matchers fail closed by design.
- Contributions are accepted under the project CLA (one click on your first PR).

## Scope
This repo is the complete open-source core: model, ingesters, rules, evidence
chain, compiler, drift detection, telemetry, Action. Hosted/team features are
developed elsewhere and are out of scope here.

## Development
```bash
pip install -e ".[dev,terraform]"
pytest -q
```
