# Security Policy

## Reporting a vulnerability
Email security@attestral.dev. You'll get an acknowledgment within 48 hours
and a fix-or-mitigation plan within 7 days for confirmed issues. Please do
not open public issues for vulnerabilities.

## Scope
The `attestral` package and this repository's GitHub Action. Include a
reproduction; the demo project in `examples/` is a good base.

## Intentionally vulnerable fixtures
Manifests under `examples/` (for instance `examples/vulnerable-deps/` and
`examples/langgraph-cve-chain/`) deliberately pin dependency versions with
published CVEs. They are static scan fixtures that exercise Attestral's
known-CVE detections (ATL-117, ATL-145); they are never installed by the
package, the test suite, or CI. Dependabot alerts on these paths are
dismissed as `not_used` by policy - do not report them, and do not "fix"
the pins, since upgrading them would break the detections they exist to
prove.

## Design commitments
- Fail-closed: unknown rule matchers never match; compilation defaults to deny.
- No `eval`/`exec` anywhere in the rule path.
- The evidence chain is deterministic and verifiable offline.
