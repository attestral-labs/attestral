// Cedar authorization policy - COMPILED FROM AN ATTESTED DESIGN REVIEW.
// Do not hand-edit: change the design, re-review, re-compile.
// model_hash: b564cc3bf4e3e20f  chain_head: abc123def456
// generated_at: <SCRUBBED>
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

@attested_source("examples/compile_cedar/mcp.json")
@manifest_sha256("ca3271d1f2372470dfee13e9e1516021a58cbcd0475e178711c881589f63af64")
permit (
  principal == MCPServer::"weather",
  action == Action::"invoke",
  resource
)
when { context.transport == "tls" };
