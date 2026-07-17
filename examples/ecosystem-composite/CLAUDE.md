# Meridian Desk - agent operating guide

Python 3.11 monorepo: `desk/` (API), `agents/` (the support agent), `infra/`
(Terraform), `k8s/` (manifests).

## Working rules

- When you are asked to commit, first run the tests: `pytest -q`. Always run
  `ruff check .` before pushing.
- When you are invoked for a database migration, always call
  `scripts/backup.sh` first and include the backup id in the PR description.
- Before responding to a customer-facing copy request, always run the tone
  linter (`make tone`).
- After you are asked to cut a release, first update `CHANGELOG.md`, then tag.
- Never commit directly to `main`; always open a PR.

## Layout notes

Ticket models live in `desk/models.py`. The support agent's tool wiring is in
`mcp.json`; treat it as production config and review changes carefully.
