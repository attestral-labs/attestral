# Vector store shared across users by one static credential (LLM08)

A single MCP server exposes a vector database (Chroma) reached through one static
API key in its environment:

```json
"knowledge-base": {
  "args": ["-y", "@chroma-core/chroma-mcp@0.3.1"],
  "env": { "CHROMA_API_KEY": "ck-live-...", "CHROMA_TENANT": "default" }
}
```

Every user's embedded data lands in one store behind that one key. If the agent
serves more than one user, a query - or a prompt injection steering one - can
retrieve or poison another tenant's vectors. There is no per-tenant boundary at
the store, so one key grants every user the union of everyone's data.

```bash
attestral scan examples/vector-store-tenancy
```

Fires **ATL-149** (medium, `OWASP LLM08 Vector and Embedding Weaknesses`). This is
distinct from the public-endpoint confused-deputy case: ATL-115 and the
shared-identity fleet rule need an exposed endpoint as the multi-caller side,
whereas the cross-tenant embedding leak exists for a purely internal multi-user
agent with no endpoint at all. ATL-104 (secret in env), ATL-105 (auto-install),
and ATL-114 (memory store as a poisoning target) fire alongside it, each a
different property of the same server.

## The fix

Partition the store per tenant (a namespace or collection per user, or
per-tenant credentials), or exchange the caller's own identity for a scoped,
short-lived credential per request, so a query can only reach the caller's own
vectors.

## Research

- **OWASP Top 10 for LLM Applications 2025 - LLM08 Vector and Embedding
  Weaknesses** (cross-tenant leakage, missing access control at the store).
- **OWASP Top 10 for Agentic Applications 2026 - ASI06** (memory / context) and
  **ASI03** (identity and privilege).
