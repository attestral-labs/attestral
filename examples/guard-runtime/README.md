# Guard runtime fixture

Two filesystem MCP servers that compile to opposite verdicts, so the
enforcement point (`attestral guard`) has both a server it must let load and one
it must refuse. This fixture pins the compile-to-guard path: scan it, compile
it, and enforce the policy live.

```bash
attestral scan examples/guard-runtime
```

- `docs` is rooted at `/srv/docs` - a **specific project subdirectory**, the
  correct way to scope a filesystem server. It classifies as `project`, does not
  fire ATL-102, and compiles to `allow: true` with its filesystem scope narrowed
  to `root_paths: [/srv/docs]`.
- `root-files` is rooted at `/` - the **whole machine**, so it fires **ATL-102**
  and compiles to `allow: false` (denied by the attested design review).

```
2 components · 1 finding · 1 high
```

## What the guard does with it

```bash
# compile the reviewed design into a default-deny policy
attestral compile examples/guard-runtime -o policy.yaml

# refuse the denied server: it never launches (exit 3), nothing runs
attestral guard policy.yaml --server root-files -- npx @modelcontextprotocol/server-filesystem /

# enforce the allowed server: it loads, but every tools/call is gated -
# a read inside /srv/docs is forwarded, a read of /etc/passwd comes back as a
# JSON-RPC error (DRF-003) and never reaches the server
attestral guard policy.yaml --server docs -- npx @modelcontextprotocol/server-filesystem /srv/docs
```

Every decision is appended to `policy.yaml.telemetry.jsonl` in the exact schema
`attestral drift` reads, so the same run that enforces the policy also produces
the event stream the rest of the runtime loop (`drift`, `lockdown`, `incident`)
reasons over. The verdict the guard enforces per call is computed by the same
`drift.evaluate_event` the detector uses, so enforcement and detection can never
disagree.
