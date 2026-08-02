# Design-diff demo: the base revision

Paired with `examples/diff-widened`. A small agent-plus-cloud design with a
deliberately narrow capability envelope: `web` fetches pages (an outbound
channel that also ingests untrusted web content), `ops` is a deploy runner
that so far holds no capability tokens at all, and the cloud side is a single
S3 bucket. No shell, no standing credentials, no edge from the agent runtime
into the cloud boundary.

```bash
attestral scan examples/diff-base
```

3 components · 3 findings · 1 high · 1 medium · 1 info

| Rule | Severity | Why |
|---|---|---|
| ATL-105 | high | `web` auto-installs its package at launch (`npx -y`). |
| ATL-107 | medium | `web` grants outbound network / browser access. |
| ATL-201 | info | Agent runtime and cloud share no declared boundary controls. |

The pair exists to exercise `attestral design-diff` - the capability-envelope
gate for PRs:

```bash
attestral design-diff examples/diff-base examples/diff-widened --fail-on-widen
```

The widened revision gives `ops` a shell, standing AWS keys, and (through
those keys) a `credential_reach` edge into the bucket - four widening signals,
verdict WIDENED, exit code 3. The same command with identical paths on both
sides is UNCHANGED and exits 0.
