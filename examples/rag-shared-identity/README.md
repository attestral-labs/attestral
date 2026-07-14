# Shared-identity data access fixture (ASI03)

A `knowledge-assistant` agent exposed over a public A2A endpoint, answering
questions from a team knowledge base held in a `qdrant` vector store. The store
is reached through one static `QDRANT_API_KEY`. The danger is structural:
**every external caller reads with the same downstream identity**, so per-caller
entitlements can never be enforced at the store - the confused deputy at the
data layer.

```bash
attestral scan examples/rag-shared-identity
```

```
3 components · 6 findings · 1 critical · 3 high · 2 medium
```

## What fires, and why

| Rule | Severity | Where | Risk |
|---|---|---|---|
| ATL-208 | critical | *(fleet)* | External agents can reach sensitive tools through the public endpoint. |
| **ATL-211** | high | `qdrant` | **The identity gap.** A publicly callable endpoint fronts a data store reached through a single static service credential; caller identity is never propagated, so the store cannot tell one caller from another. |
| ATL-121 | high | `knowledge-assistant` | The agent card declares no authentication at all. |
| ATL-105 | high | `docs` | The docs server auto-installs its package at launch (`npx -y`). |
| ATL-104 | medium | `qdrant` | The store credential is passed in `env`. |
| ATL-114 | medium | `qdrant` | A persistent memory/vector store is configured: retrieved content must be treated as untrusted input. |

ATL-121, ATL-104, and ATL-114 are each visible to a per-component scanner.
**ATL-211 is not** - the public endpoint and the shared-credential store are
each unremarkable alone; the finding exists only because both sides live in the
same system model. This is the RAG-era version of the confused deputy: the
agent is one principal downstream no matter how many principals it serves
upstream.

## The right fix

Exchange each caller's identity for a scoped, short-lived downstream credential
(OAuth 2.0 Token Exchange, RFC 8693) or enforce per-caller authorization at
retrieval. Rotating the shared key changes nothing; the gap is architectural,
which is why it must be caught at design time.
