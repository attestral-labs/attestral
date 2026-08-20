# FastMCP server implementation - lethal trifecta

`1 component · 5 findings · 1 critical · 4 high`

A single MCP **server implementation** written against the FastMCP SDK - not a
client `.mcp.json` config - whose tools together form the lethal trifecta:

- `fetch_url` - fetches any web page (untrusted external input + network)
- `read_file` - reads local files (private data, e.g. keys and notes)
- `run_command` - runs a shell command (code execution)
- `send_webhook` - posts to an external endpoint (egress)

One injected instruction can read a secret and send it out. Attestral ingests the
**server implementation itself**, via the `mcp` / FastMCP recognition in the
agent-code ingester (a Python server that ships no client config is still
reviewed), and fires the lethal trifecta (ATL-202) plus the toxic-flow (ATL-207)
and shell-plus-network (ATL-203) findings. Validated against the same pattern in
Damn Vulnerable MCP challenge 2 (external real-world recall, 2026-08-19).

```sh
attestral scan examples/fastmcp-trifecta
```
