# Reference fleet: a realistic agentic company

Not a deliberately-broken teaching fixture. This is a plausible small SaaS,
"Larkspur", wired the way a real team wires an agent estate under deadline: two
agents in two repos, each defensible on its own review, sharing a cloud. It
exists so you can point a skeptic at something that looks like production and ask
"does it actually find the thing that matters." It does, and the thing that
matters only shows up across the two repos.

## The system

- **`support-agent/`** - a customer-support agent (LangGraph, `agent.py`) with an
  MCP fleet: a web knowledge-base fetcher, a Zendesk reader (token in `env`), and
  a Slack notifier (token in `env`). It ingests untrusted content (help-center
  pages, tickets) and can post outbound. No shell.
- **`ops-agent/`** - an SRE agent with a runbook shell tool and a Postgres reader
  (connection string in `env`), plus the Terraform for the platform it operates:
  a public "customer-exports" S3 bucket, the prod database, and a wildcard IAM
  role. It can run commands. No untrusted-input tool.

## What a single-repo review sees

```bash
attestral scan examples/reference-fleet/support-agent
attestral scan examples/reference-fleet/ops-agent
```

Each repo raises real, act-on-it findings on its own: the support agent's lethal
trifecta and env secrets (ATL-202, ATL-104), the ops agent's public bucket,
wildcard IAM, shell server, and RDS without IAM auth (ATL-001, ATL-003, ATL-103,
ATL-056). Useful, but each looks like a normal ops review.

## What only the fleet sees

```bash
attestral fleet examples/reference-fleet/support-agent examples/reference-fleet/ops-agent
```

```
cross-repo chain: entry [support-agent] -> pivot [ops-agent] -> impact [support-agent]
```

Neither repo completes an attack chain alone: support has the untrusted entry and
the exit but no way to run code; ops has the shell but nothing untrusted driving
it and no exit. Together they do. `attestral fleet` fires **ATL-213**: a help-page
the support agent reads carries an injected instruction, the support agent
delegates to the ops runbook which runs it, and the result leaves over the
support agent's Slack or fetch tool. That is the flow a per-repo scanner, however
good, cannot see, on a system that looks like a real company's.

Everything here is fictional (the tokens, the company). It exists to be scanned.
