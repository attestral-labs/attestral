# deployment-concentration

The LiteLLM-class credential concentration where it actually lives: a
`docker-compose.yml` running an LLM gateway that sources five providers' keys,
and a `.env` file that concentrates the deployment's real key set in one place.

A holistic sweep of 390 popular MCP repositories found this pattern in **zero**
committed `.mcp.json` files, because committed configs do not ship provider keys
in env. They ship in the deployment, so `ATL-168` reviews the two surfaces a small
team actually uses: a compose service and a `.env`. It is the deployment-surface
counterpart to `ATL-164` (MCP config) and `ATL-165` (Kubernetes).

- the compose `llm-gateway` service and the `.env` each hold four or more distinct
  providers, so both fire `ATL-168`;
- the single-provider `notes` service is silent, so the rule keys on
  *concentration*, not on any single secret.

```
3 components · 2 findings · 2 high
```

A `.env.example` template in the same directory would be skipped: it documents the
shape but is not the deployment's live key set. The fix is the same as the MCP and
Kubernetes layers: front the providers with a credential broker that mints a
short-lived, scoped token per call, split them across isolated services, and never
commit a real `.env` to version control.
