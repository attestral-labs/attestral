# PR: Native Attestral-format telemetry (JSONL)

## What
Adds `attestral_telemetry.TelemetryWriter`, an append-only, thread-safe JSONL
emitter called after each proxy allow/deny decision. One line per event:

```json
{"ts":"2026-07-10T14:01:02Z","server":"docs","tool":"read_file","args":["/srv/docs/x.md"],"decision":"allow"}
```

## Why
This is the exact schema consumed by `attestral drift`, which diffs runtime
behavior against an attested design review. With this emitter, mcp-guard users
get design-runtime conformance checking with zero glue code:

```bash
attestral compile ./infra -o policy.yaml # attested design → policy
attestral drift policy.yaml guard-events.jsonl --fail-on-drift
```

Denied attempts are logged too - a blocked call is still evidence that
deployment and reviewed design disagree.

## Design notes
- Thread-safe (single lock around append), size-based rotation, and rotation
 failures never propagate into the request path (fail-open for telemetry,
 fail-closed for enforcement - the proxy's decision is never affected).
- No new dependencies (stdlib only).
- Config suggestion: `telemetry: { format: attestral, path: ./guard-events.jsonl }`

## Testing
Unit tests cover emit format, thread-safety under concurrent emits, and rotation.
