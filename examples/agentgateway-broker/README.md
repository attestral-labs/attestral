# agentgateway-broker

An agentgateway credential-broker config with two routes: one that fails open and
inlines its client secret, and one that is configured correctly. It exercises the
second job the CB4A draft frames for a design review - not "does the agent hold a
standing key" (ATL-104/164/165) but "does the declared broker actually eliminate
it, or is it a broker in name only".

- `fails-open` runs `jwtAuth: mode: permissive`, so an unauthenticated caller
  reaches a credentialed egress (`ATL-166`, CB4A TM-9), and it commits a literal
  `clientSecret` in the config (`ATL-167`, CB4A TM-1).
- `well-configured` runs `jwtAuth: mode: strict` and sources its secret from a
  `secretRef`, so it brokers the credential correctly and stays silent.

```
2 components · 2 findings · 2 high
```

The ingester recognizes both the standalone `binds` config and the Kubernetes
`AgentgatewayPolicy` CRD. The point is that a credential broker is only worth
deploying if it fails closed and holds no reusable secret of its own; a broker
that fails open, or that hardcodes its own OAuth client secret, reintroduces the
exact risk it was meant to remove.
