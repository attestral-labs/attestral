<!--
Thanks for contributing to Attestral. Fill in the sections below and check the
boxes. The full guidance is in CONTRIBUTING.md; this is the short version.
-->

## What and why

<!-- One or two sentences: what does this change do, and what problem does it solve?
     Link the issue it closes, e.g. "Closes #123". -->

Closes #

## How it was verified

<!-- Paste the relevant output or name the test that covers it. -->

- [ ] `.venv/bin/pytest -q` passes (run from the repo root; `testpaths` is pinned to `tests/`)
- [ ] `.venv/bin/ruff check attestral/ tests/` is clean
- [ ] New behavior has a test (a new rule needs a fixture under `examples/` and a test asserting it fires)

## Checklist

- [ ] Commits are signed off (`git commit -s`) per the [DCO](https://developercertificate.org/) (see CONTRIBUTING.md)
- [ ] New detection rules are pure-data YAML with a matcher from the fail-closed set (no executable logic in rule files)
- [ ] Framework citations (OWASP-AgSec / CIS / NIST) are real controls, not decoration
- [ ] No files are written by a scan unless `-o` / `--format` is passed (terminal-first)
- [ ] Heavy imports (`transformers`, `torch`, `anthropic`) stay lazy inside functions
- [ ] Docs stay in sync: a new module is drawn in the README diagram, a new command has a usage example, a release has a CHANGELOG entry (the suite enforces this)

<!--
CI runs the test matrix and an automated Claude review on every PR. A maintainer
(@zeyadalsakhii) reviews and merges; main is protected, so nothing lands without
a green build and a code-owner approval.
-->
