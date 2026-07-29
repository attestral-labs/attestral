# broker-bypassed

A system that declares a credential broker but does not route everything through
it. The `agentgateway.yaml` route is correctly configured (strict inbound auth, a
`secretRef` secret), yet the `.mcp.json` still runs a Notion server that holds a
standing `NOTION_API_KEY` in its own env.

That combination is the CB4A "Model C in disguise" (TM-11 broker bypass): the
broker was meant to be the only path to a credential, but a raw standing key sits
right beside it, so an injection or a compromise gets the key and skips the broker
entirely. `ATL-221` fires only because a broker is present; a raw credential with
no broker is plain sprawl (ATL-104), not a bypass, and stays silent here.

```
2 components · 3 findings · 2 high · 1 medium
```

This is the finding only the system model can make: the broker route and the
raw-credential holder live in different files, and neither one alone is wrong.
The fix is to route the Notion credential through the broker too and remove the
standing key, so the broker really is the exclusive credential path.
