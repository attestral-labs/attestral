# Registry manifest namespace that matches none of its sources

A `server.json` that claims the reverse-DNS namespace `com.acmepay/payments-mcp`
- the namespace only the owner of **acmepay.com** may publish under - while its
repository lives at `github.com/zylo-labs/...` and its remote endpoint at
`payments-mcp.zylo-labs.dev`. Name points one way; code and endpoints point
somewhere else entirely.

```bash
attestral scan examples/registry-namespace-mismatch
# 1 component · 1 finding · 1 medium   (ATL-159)
```

## Why the mismatch is the finding

In the MCP registry's namespace-verification model the name IS the trust
signal: `com.example/*` requires a DNS or HTTP challenge on example.com, and
`io.github.*` requires the GitHub login. But a manifest consumed *outside* the
official registry - vendored into a repo, mirrored, or served from a
self-hosted registry - never went through that ownership check, so a name
squatting a brand's domain rides on trust the publisher never earned. The
mismatch between the claimed domain and every declared source is the statically
visible shape of that impersonation.

## What does NOT fire

`ATL-159` compares only when it has something to compare, and clears every
legitimate layout:

- a matching namespace (`com.acme` with a remote on `mcp.acme.com`) is silent;
- forge namespaces (`io.github.*`, `io.gitlab.*`) are account-verified, not
  domain-verified - a remote on any host is consistent with them, so they are
  never compared (see `examples/mcp-registry`, which stays unchanged);
- a forge-hosted repository owned by the same organization (`com.zylo` with
  `github.com/zylo/...`) is recognized as matching - the normal open-source
  layout never fires;
- no repository and no remotes means nothing to compare: fail closed, no
  finding.

## Research

- **MCP Registry namespace verification** (official registry requirements):
  DNS/HTTP-challenge proof for `com.example/*`, GitHub login for `io.github.*`.
- **CWE-829** (Inclusion of Functionality from Untrusted Control Sphere) /
  **NIST SR-4** (supply-chain provenance).
- **OWASP-ASI04:2026** (agentic supply chain).
