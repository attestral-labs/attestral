# Secret hard-coded in an agent-instruction file (LLM07)

A `CLAUDE.md` that carries live credentials in its text: a GitHub token and a
Postgres connection string with an inline password.

```
The deploy token is ghp_... and the status database is at
postgres://deploy:S3cr3t-Passw0rd-99@db.internal:5432/prod.
```

Instruction files are the worst place to keep a secret. They are committed to
version control (so the secret is in the history forever, even after you delete
it), shared across a team, copied into logs and error reports, and read back into
the model's context on every single run. A credential placed here leaks along all
of those paths at once.

```bash
attestral scan examples/prompt-embedded-secret
# 1 component · 1 finding · 1 high   (ATL-151)
```

`ATL-151` detects the secret by **shape**, never by guessing: a provider prefix
(`ghp_`, `AKIA`, `xox...`), a private-key block, or a connection string with an
inline password. The generic `key = value` case additionally requires a long,
high-entropy value that is not a placeholder, so benign guidance like
`api_key: <your-key-here>` or "read `DATABASE_URL` from the environment" does not
fire.

## The fix

Remove the secret and rotate it - assume it is compromised the moment it was
committed. Reference credentials from a secret manager or an environment variable
the agent reads at run time, never inline in prompt or instruction text.

## Research

- **OWASP Top 10 for LLM Applications 2025 - LLM07 System Prompt Leakage**
  (secrets embedded in the prompt) and **LLM02 Sensitive Information Disclosure**.
- **OWASP Top 10 for Agentic Applications 2026 - ASI06** (memory / context) and
  **CWE-798** (use of hard-coded credentials).
