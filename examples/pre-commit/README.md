# attestral pre-commit hook

Run attestral automatically on every commit so infra and agent-config risks are
caught before they land - no CI round-trip required.

## Setup

1. Install [pre-commit](https://pre-commit.com):

   ```sh
   pip install pre-commit    # or: brew install pre-commit
   ```

2. Copy [`.pre-commit-config.yaml`](./.pre-commit-config.yaml) to the **root** of
   your repository (merge it into an existing one if you already have hooks).

3. Install the git hook:

   ```sh
   pre-commit install
   ```

That's it. Every `git commit` that touches a `.tf`, `.yaml`/`.yml`, or MCP config
(`mcp.json`, `*.mcp.json`, `claude_desktop_config.json`) now runs attestral and
**blocks the commit on any high- or critical-severity finding**.

## Hooks provided

| id | What it does | Runs when |
|----|--------------|-----------|
| `attestral`       | Scans the Terraform / Kubernetes / MCP config committed in this repo. | An infra/agent config file changed. |
| `attestral-local` | Audits the MCP servers installed on the developer's machine (Claude Desktop, Cursor, VS Code, Windsurf). | Every commit. |

The `attestral` hook scans the whole repository (attestral builds one
cross-boundary model), but only *fires* when a relevant file is staged.

## Customizing the gate

The default is `--fail-on=high`. Override it per repo via `args`:

```yaml
- id: attestral
  args: [".", "--fail-on=medium", "--format=json"]
```

## Ignore the report artifact

The hook writes a machine-readable `attestral-report.json` to the repo root.
Add it to your `.gitignore`:

```gitignore
attestral-report.*
```

## Run it manually

```sh
pre-commit run attestral --all-files        # scan the repo now
pre-commit run attestral-local --all-files  # audit installed MCP servers now
```
