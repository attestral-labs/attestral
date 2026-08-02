# Design-diff demo: the widened revision

Paired with `examples/diff-base`. Same design, one PR later, and nothing in
the diff looks dramatic: `ops` swapped its launcher for `bash` and gained two
env vars. But that quiet change widens the capability envelope three ways -
`ops` now holds a shell capability, standing AWS keys in env, and cloud
credentials that open a `credential_reach` edge from the agent runtime into
the S3 bucket. With `web` still ingesting untrusted web content, the fleet now
has a full injection-to-cloud path, and the model-level rules light up.

```bash
attestral scan examples/diff-widened
```

3 components · 10 findings · 1 critical · 8 high · 1 info

| Rule | Severity | Why |
|---|---|---|
| ATL-103 | critical | `ops` is a shell-capable server - the pivot of the walked attack path. |
| ATL-112 | high | `ops` holds raw cloud credentials, a live agent-to-cloud crossing. |
| ATL-203 / ATL-207 / ATL-216 / ATL-217 | high | Model-level: shell plus outbound reach, untrusted input reaching execution, injection reaching cloud credentials, and the information-flow violation. |
| ATL-104 | high (raised) | The AWS secret rides in on env, on the walked chain. |

The point of the pair is the gate, not the scan:

```bash
attestral design-diff examples/diff-base examples/diff-widened --fail-on-widen
```

renders the four widening signals and the newly-firing rules, ends with
`verdict: WIDENED`, and exits 3 - the PR that quietly widened what the agent
can reach becomes a red build.
