# Blast-radius demo: three surfaces, three very different reaches

Three MCP servers share one agent runtime, so any one of them, if an injection
lands in it, can induce the agent to call the other two. What separates them is
what each one *holds directly*:

- `admin-runner` runs a shell (`bash`), carries AWS credentials (a cloud
  crossing), and touches a `postgres` database. Three high-weight sinks, all at
  hop 0. It is the lethal-trifecta host and tops the ranking on its own.
- `web-fetch` holds only an outbound channel (`network`). Compromised, its worst
  reach is what it can pivot into through its siblings.
- `notes` holds only persistent `memory`, the lowest-weight sink.

`attestral blast-radius examples/blast-radius-demo` ranks `admin-runner` far
above the other two: a sink a surface holds directly counts for full weight,
one it can only reach by pivoting through a sibling is discounted by distance.
The score is a prioritisation signal over the declared design, not a proof that
an injection would succeed.
