# Literal auth token committed in a remote MCP server's headers

Two remote servers, one mistake. `crm-bridge` embeds a literal bearer token in
its `headers` block, so the credential lives in version control - it ships to
everyone who clones the repo, lands in logs and backups, and cannot be rotated
out of the history. `issue-tracker` does it right: `${TRACKER_API_KEY}` env
indirection keeps the config credential-free.

```bash
attestral scan examples/mcp-header-token
# 2 components · 1 finding · 1 high   (ATL-157)
```

## Why only `crm-bridge` fires

`ATL-157` fires **only** on a literal committed value in an auth-shaped header
(`Authorization`, `X-API-Key`, token/secret-shaped keys). It deliberately stays
silent on everything that is correct or unresolvable:

- `${ENV_VAR}` / `$VAR` indirection is the recommended pattern - never flagged;
- an OAuth-per-spec endpoint carries no header at all (the MCP authorization
  spec, 2025-11-25, has the client obtain a short-lived token at connect time) -
  that absence is expected, not a finding (see the ATL-109 OAuth-awareness);
- placeholder values (`<token>`, `REDACTED`, `changeme`) fail closed, so a
  sanitized example config is never flagged.

Both endpoints are authenticated, so neither trips ATL-109: the finding here is
not missing auth, it is *where the credential lives*.

## Research

- **MCP authorization specification** (2025-11-25): HTTP transports use OAuth
  with short-lived tokens obtained at connect time, precisely so no static
  credential sits in a client config.
- **CWE-798** (Use of Hard-coded Credentials) / **NIST IA-5(7)** (no embedded
  unencrypted static authenticators).
- **OWASP-ASI03:2026** (identity and credential abuse in agentic systems).
