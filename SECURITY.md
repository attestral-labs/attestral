# Security Policy

## Reporting a vulnerability
Email security@attestral.dev. You'll get an acknowledgment within 48 hours
and a fix-or-mitigation plan within 7 days for confirmed issues. Please do
not open public issues for vulnerabilities.

## Scope
The `attestral` package and this repository's GitHub Action. Include a
reproduction; the demo project in `examples/` is a good base.

## Design commitments
- Fail-closed: unknown rule matchers never match; compilation defaults to deny.
- No `eval`/`exec` anywhere in the rule path.
- The evidence chain is deterministic and verifiable offline.
