# Admit demo: should this agent load this tool?

The base design for `attestral admit`. One MCP server, `aws-deploy`, holds AWS
credentials that reach three named resources (`aws_s3_bucket.customer_data`,
`aws_iam_role.deployer`, `aws_dynamodb_table.sessions`). On its own the design is
fine: the credentialed server is expected to reach the cloud, and there is no
injectable surface to launder an injection through.

The question `admit` answers is what happens when you ADD a tool:

```sh
# DENY - a read-only web fetcher is harmless alone, but dropped into this
# runtime it becomes the injectable entry of a confused-deputy path (ATL-222):
attestral admit examples/admit-base --add examples/admit-add-deny
#   ADMIT: DENY  web-fetch
#   deny: admitting completes ATL-222 ... reach into aws_s3_bucket.customer_data

# ALLOW - a pinned, capability-free clock server grants no new reach:
attestral admit examples/admit-base --add examples/admit-add-allow
#   ADMIT: ALLOW  clock
```

The verdict is the security delta of admitting the tool, not a rule on the tool:
the fetcher is only dangerous because of the fleet it joins, which is exactly the
whole-system property a per-server scanner cannot compute. Use it as a PR-time or
install-time gate with `--fail-on-deny`.
