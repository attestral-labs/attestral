# CI agent confused-deputy fixture (CVE-2026-54316)

Two GitHub Actions workflows that model the design-time surface behind
CVE-2026-54316 (Novee Security, Black Hat USA 2026): an AI coding agent wired
into CI that an unprivileged GitHub issue can steer into runner secrets. The
danger is a four-part conjunction no single-file check can see - each half is
routine on its own; together they are a confused deputy.

```bash
attestral scan examples/ci-agent-confused-deputy
```

```
2 components · 1 finding · 1 critical
```

The scan fires **ATL-223** (critical) on the `triage` job and stays silent on
the benign `ci` job. Each workflow job lands as a `ci_workflow` component in the
`ci` trust boundary with four derived attributes, and ATL-223 matches only the
four-way conjunction - so a normal build pipeline never trips it.

## The two workflows

**`triage.yml`** - the confused deputy. All four signals light up:

| Attribute | Why it is true |
|---|---|
| `_untrusted_trigger` | `on: issues` / `issue_comment` - any GitHub account can fire the workflow (`_untrusted_triggers` lists both) |
| `_invokes_ai_agent` | a step `uses: anthropics/claude-code-action` (`_ai_agent` names it) |
| `_secrets_in_scope` | `${{ secrets.SOME_API_KEY }}` plus a `contents: write` token grant (`_secret_refs` lists both) |
| `_agent_step_has_shell` | the agent's `with.allowed_tools` enables `Bash(git:*)` |

An attacker opens an issue, the issue body becomes agent input, the agent
holds a shell, a repo secret, and a write-capable `GITHUB_TOKEN`. That is
prompt injection to code execution to secret exfiltration, from an account
with zero repository permissions.

**`ci.yml`** - the benign counterpart. `on: push`, `contents: read`, no
secrets beyond the implicit token, no agent. Its `ci_workflow` component
emits with all four signals false, which is exactly what keeps the future
rule quiet on a normal build pipeline.

## Why this needs a system model

A YAML linter can flag `pull_request_target` or a `write-all` grant, but the
CVE-2026-54316 shape is the *join*: untrusted trigger AND agent AND secrets
AND shell, on the same job. Attestral ingests each half as a fail-closed
derived attribute so a cross-boundary rule can match the conjunction and cite
the evidence lists.
