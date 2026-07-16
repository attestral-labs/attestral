# Grounded benchmark: does it actually work?

The fair question a skeptic asks is not "is the idea cool" but "does it find real
things on systems that look real, without drowning me in noise." This page is the
answer, in two parts: a realistic system we fully control and can show in the
open, and a run against real public code.

## Part 1: a realistic system, shown in full

[`examples/reference-fleet/`](../examples/reference-fleet/) is "Larkspur", a
plausible small SaaS: a **support agent** (LangGraph, a web KB fetcher, a Zendesk
reader, a Slack notifier) and an **ops agent** (a runbook shell tool, a Postgres
reader) in two repos, sharing a cloud (a public exports bucket, the prod
database, a wildcard IAM role). Nothing is a cartoon; it is wired the way a team
wires this under deadline.

**Each repo, reviewed alone, raises real findings** and looks like a normal ops
review:

- support agent: the lethal trifecta across its tools (ATL-202), env secrets
  (ATL-104), auto-installed packages (ATL-105), and untrusted-input-into-memory
  (ATL-214).
- ops agent: a public S3 bucket (ATL-001), a wildcard IAM policy (ATL-003), a
  shell-capable server (ATL-103), and RDS without IAM auth (ATL-056).

**Only the fleet sees the thing that matters:**

```bash
attestral fleet examples/reference-fleet/support-agent examples/reference-fleet/ops-agent
# cross-repo chain: entry [support-agent] -> pivot [ops-agent] -> impact [support-agent]
# ATL-213  Cross-repo toxic flow - the fleet completes an attack chain no single repo does
```

Neither repo completes an attack chain by itself: support has the untrusted entry
and the exit but no way to run code; ops has the shell but nothing untrusted
driving it and no exit. A help page the support agent reads carries an injected
instruction, it delegates to the ops runbook which runs it, and the result leaves
over Slack. **That flow is invisible to any per-repo scanner** and is the whole
reason for building a system model. `tests/test_reference_fleet.py` pins it, so
it cannot silently regress.

## Part 2: real public code

Attestral was run against real, popular public MCP-server and agent repositories
at pinned commits (the harness is `research/mcp-ecosystem/scan_ecosystem.py`).
Aggregate, no repo named here (per the responsible-disclosure policy in
[`gallery-disclosure-plan.md`](gallery-disclosure-plan.md)):

- It reviews the **documented launch configuration** a project ships, not its
  source. Every hit is a **configuration default, not an exploited vulnerability**.
- Real findings surfaced on real repos, including a **remote MCP server with no
  authentication**, a **published registry manifest pinned to a mutable version**
  (a rule added in v0.17.0, firing on genuinely current code), and
  **injection-shaped text in a tool description** (the ML layer).
- Repos that ship **no committed config came back clean**, no false-positive
  spew. The signal-to-noise held on real code.

The larger 33-server aggregate, its full methodology, and the honest
false-positive read live in [`../evaluation/real-world.md`](../evaluation/real-world.md).
The named per-repo gallery is staged for responsible disclosure before publication.

## Reproduce it

```bash
pip install attestral
attestral scan examples/reference-fleet/support-agent          # a single repo
attestral fleet examples/reference-fleet/support-agent examples/reference-fleet/ops-agent
python -m evaluation.score                                     # the CI benchmark
```

Both parts are the same posture the project takes everywhere: show the real
output, name the limits, and let the result speak.
