# Agent-cloud confused deputy: reach into named infrastructure

The moat a per-server scanner cannot reach. Two MCP servers share one agent
runtime, and a small Terraform footprint sits in the cloud boundary:

- **`web-fetch`** ingests untrusted web content (a `network` capability) and
  holds **no credential of its own**. On its own it is a benign fetcher.
- **`aws-deploy`** carries AWS credentials (`AWS_ACCESS_KEY_ID` / `SECRET`), so
  the ingester draws `credential_reach` edges from it to every same-provider
  resource: `aws_s3_bucket.customer_data`, `aws_iam_role.deployer`,
  `aws_dynamodb_table.sessions`.

Neither server alone is the finding. The whole-system model is: a prompt
injection in `web-fetch` can be laundered through the co-resident `aws-deploy`
deputy's standing credential to reach those **named** cloud resources. That is
**ATL-222** - the agent-to-cloud confused deputy as a graph property, ending at a
concrete IaC sink that lives in the cloud model, not in any MCP server. It is
distinct from ATL-115 (a server that is itself a deputy) and ATL-112 (a server
that merely holds a cloud credential): ATL-222 fires only when the injectable
entry and the credentialed deputy are **different** components, and it names the
resource at the end of the path.

```
5 components · 7 findings · 4 high · 2 medium · 1 info
```

The other findings are the parts ATL-222 composes: `ATL-104` (secrets in
`aws-deploy` env), `ATL-112` (the cloud credential itself), `ATL-105`/`ATL-107`
(the fetcher's unpinned launch and open egress), plus the model-level fleet
findings. Remove the co-residence (isolate the fetcher into its own session) or
broker the deputy's egress and ATL-222 goes silent - the named path is gone.
