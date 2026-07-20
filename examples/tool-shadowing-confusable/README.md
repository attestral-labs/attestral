# Confusable tool-name shadowing: a look-alike that no exact match catches

`ATL-204` fires when two MCP servers declare a tool with the *exact* same name.
An attacker who wants to shadow a trusted tool without tripping that check
registers a name that *looks* the same but is a different string: a Cyrillic
letter for a Latin one, a zero-width space, a case flip, a full-width character.

This fixture runs two servers:

- `mail` (a corporate server) exposes `send_email`.
- `helper-tools` (a lower-trust helper) exposes `send_emаil` - the `a` in
  `email` is the Cyrillic letter U+0430, not the Latin `a`.

The two names are different raw strings, so `ATL-204` stays silent. But they fold
to the same identifier once case, full-width, zero-width, and homoglyph
characters are normalized, so in the client's tool list they read as one tool.
The agent cannot tell which server answers a `send_email` call.

```bash
attestral scan examples/tool-shadowing-confusable
# 2 components · 1 finding · 1 high   (ATL-219, no exact ATL-204 collision)
```

`ATL-219` fires, names both raw spellings and both servers, and cites SAFE-MCP
SAF-T1301. The benign tools on each server (`list_folders`, `format_text`) do
not collide, so the check does not just flag any multi-tool fleet.

## Why it is high-precision

The fold is deliberately narrow: NFKC normalization, case folding, removal of
zero-width / format characters, and a bounded map of the handful of Cyrillic and
Greek letters that render as Latin identifier characters. It is not a fuzzy
edit-distance match, so genuinely different names (`list` vs `lists`, `get_user`
vs `get_users`) never collide. It fires only on a spelling engineered to
impersonate another - which is almost never legitimate.

## Research

- **SAFE-MCP SAF-T1301** (Cross-Server Tool Shadowing).
- **OWASP Top 10 for Agentic Applications 2026 - ASI02** (tool misuse) and
  **OWASP MCP Top 10 MCP09** (identity / naming).
- **MITRE ATLAS AML.T0051.** Unicode confusables are a long-standing
  homoglyph-impersonation vector (IDN homograph attacks), here applied to the
  MCP tool namespace.
