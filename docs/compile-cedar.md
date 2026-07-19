# Compile to Cedar

`attestral compile --target cedar` compiles the attested design into a
[Cedar](https://www.cedarpolicy.com/) authorization policy you can load into AWS
Verified Permissions or adapt for Amazon Bedrock AgentCore. It is a second
renderer over the same intermediate representation the default `mcp-guard` target
uses, so the allow/deny decision is identical across both; only the surface
syntax differs.

```bash
attestral compile ./my-project --target cedar
# wrote attested-policy.cedar  ·  target cedar  ·  default deny  ·  2 allowed, 1 denied
```

`mcp-guard` remains the default target. Passing no `--target` writes
`mcp-guard-policy.yaml` exactly as before; there is no behavior change for
existing users.

## The mapping

The compiler builds one neutral policy dictionary from the reviewed model and its
findings, then renders it. For Cedar:

- **Server = principal.** Each MCP server is `MCPServer::"<name>"`.
- **Capability = action.** A permitted invocation is `Action::"invoke"`. The
  server's coarse capability classes ride along as an `@capabilities`
  annotation, not as separate actions.
- **Resource is unconstrained.** The scope names `resource` with no bound; the
  server principal and the invoke action carry the decision.
- **Allow becomes a `permit`.** Its constraints render as `when` conditions.
- **Deny becomes a `forbid`.** The deny reason (the rule ids that denied it)
  renders as a `//` comment directly above the statement.
- **Default is Cedar's native implicit deny.** Any server without a `permit` is
  denied, which matches mcp-guard's `default: deny`. No blanket `forbid` is
  emitted; the absence of a permit is the deny.

An explicit `forbid` overrides any `permit` in Cedar, so a denied server stays
denied even if a future permit is added by hand. That is the belt-and-braces
reason denials are emitted as real `forbid` statements rather than just omitted.

## Constraint to condition map

Each attested constraint on an allowed server becomes one sub-condition, and they
AND together in a single `when { ... }` in a deterministic order.

| Attested constraint  | Cedar condition                                      |
|----------------------|------------------------------------------------------|
| `transport: tls_only`| `context.transport == "tls"`                         |
| `root_paths: [...]`  | `["/p1", "/p2"].contains(context.root_path)`         |
| `forbid_env_secrets` | `context.env_has_secrets == false`                   |

A server with no constraints gets a `permit` with no `when` clause. Conditions
live only on `permit` statements: a missing context attribute makes a permit's
condition fail, which denies. That is fail-closed, matching Attestral's posture.
Conditions are never attached to a `forbid`, because a missing attribute there
would fail open.

Worked example:

```cedar
// Cedar authorization policy - COMPILED FROM AN ATTESTED DESIGN REVIEW.
// Do not hand-edit: change the design, re-review, re-compile.
// model_hash: b564cc3bf4e3e20f  chain_head: abc123def456
// generated_at: 2026-07-18T00:00:00+00:00
// Cedar default is implicit deny: any MCP server without a permit below is denied.
// Budgets are documentation only in Cedar (loop_repeat_threshold=5, max_calls_per_server=100).
// Cedar is a stateless per-request evaluator, so mcp-guard and attestral drift remain their enforcer.

@attested_source("examples/compile_cedar/mcp.json")
@manifest_sha256("66cefa56feb788992753b11733473c521c7b2ec4a9314e6cd0aa7141e5cbc7be")
@capabilities("filesystem")
permit (
  principal == MCPServer::"docs",
  action == Action::"invoke",
  resource
)
when { ["/srv/docs"].contains(context.root_path) && context.env_has_secrets == false };

// denied by attested design review: ATL-101
@attested_source("examples/compile_cedar/mcp.json")
@manifest_sha256("22b6a0932b3c7bc36e181eb2733f192adc74272f65131d0152d1051645340e64")
forbid (
  principal == MCPServer::"legacy",
  action,
  resource
);
```

## Budgets are documentation only in Cedar

The loop-repeat and per-server call budgets are stateful, cross-request counters.
Cedar is a stateless per-request evaluator with no notion of a running count, so
the budgets are emitted as a header comment for the reader's context and nothing
more. `mcp-guard` plus `attestral drift` remain their enforcer; do not read the
budget comment as something Cedar checks.

## AgentCore-native adaptation

The output above is portable and account-agnostic on purpose. A real Amazon
Bedrock AgentCore policy is account-specific in ways a static scan cannot supply:

- **Principal** is the OAuth user or workload identity that called the gateway,
  not the MCP server.
- **Action** is the gateway tool, typically `ToolGroup___method`.
- **Resource** is the Gateway ARN for your account and region.
- **Parameters** arrive under `context.input.*`.

To target AgentCore natively you rewrite the scope against those entities and
supply the Gateway ARN yourself. The scan cannot fill the ARN in for you, so we
frame the Cedar output as an adaptable starting point, not a drop-in
account-specific AgentCore policy.

## Limits

Cedar output is one-way and lossy relative to the neutral policy dict, so:

- It is **not a valid `--against` prior.** `attestral compile --against` diffs
  policy dictionaries; a `.cedar` file is not parseable back into one. Keep an
  mcp-guard YAML if you want to gate re-attestations as narrowings.
- **`attestral drift` cannot consume it.** Drift reads the mcp-guard YAML.
  Compile to the default target for the runtime loop; use Cedar for the
  authorization plane.

## Validation

Attestral does not vendor Cedar; emission is pure text. The output parses as a
standalone Cedar policy set, which is what we promise. Full validation is
external and optional:

```bash
cargo install cedar-policy-cli
cedar check-parse --policies attested-policy.cedar          # syntactic, no schema
cedar validate --schema your-schema.cedarschema \
               --policies attested-policy.cedar             # needs a schema you supply
```

`cedar validate` needs a schema that declares the `MCPServer` and `Action`
entities and the `context` attributes referenced above; that schema is
deployment-specific, so we do not ship one. If the `cedar` CLI is installed, the
test suite shells out to `cedar check-parse` as an optional check and skips
cleanly when it is absent.
