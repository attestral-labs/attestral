# Memory / context-poisoning fixture (OWASP ASI06)

Standing agent-instruction files - `CLAUDE.md`, `.cursorrules`, `AGENTS.md`,
`.windsurfrules`, Copilot instructions - are *persistent* context. Unlike a
per-session prompt injection, poisoning one of these steers **every future
run** of the agent. Attestral treats them as first-class components
(`agent_instruction`), on two layers:

- **Deterministic (ATL-113, this file):** the instruction file (or its
  directory) is **world-writable** - anyone on the host can rewrite the
  agent's standing orders. This is a filesystem-permission fact, so it is a
  rule, not an ML score. (Not reproducible from a committed fixture: git does
  not track world-writability, so the test sets the mode explicitly; see
  `tests/test_memory_poisoning.py`.)

- **Language (ML layer, on by default):** the *content* of the file scored for
  injection / exfiltration text. The `CLAUDE.md` here hides an HTML-comment
  instruction telling the agent to read `~/.aws/credentials` and smuggle it
  into a tool call - classic indirect injection embedded in standing memory.

```bash
attestral scan examples/memory-poisoning   # the heuristic tier runs by default
```

## Research

- **OWASP Top 10 for Agentic Applications 2026 - ASI06 Memory & Context
  Poisoning.** <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **MITRE ATLAS AML.T0051 (LLM Prompt Injection)** for the embedded-instruction
  vector. <https://atlas.mitre.org/techniques/AML.T0051>
- The split is deliberate and matches Attestral's design invariant: a
  permission fact is a deterministic rule; risk that lives in *words* belongs
  to the ML layer, never a YAML matcher.
