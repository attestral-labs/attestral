# Vulnerable-dependency fixture

A `requirements.txt` that pins agent-framework libraries to versions with
published CVEs. The vulnerability lives in the dependency tree, not in any
config an MCP or cloud ingester reads, which is exactly the surface a
design-time architecture review usually misses.

```bash
attestral scan examples/vulnerable-deps
```

Fires **ATL-145** twice:

- `langchain-core==1.2.4` - CVE-2025-68664 ("LangGrinch", CVSS 9.3), a
  serialization-injection flaw that exfiltrates environment secrets. Fixed in
  0.3.81 / 1.2.5.
- `langgraph-checkpoint-sqlite==3.0.0` - CVE-2025-67644 (CVSS 7.3), SQL
  injection in the SQLite checkpointer, chainable toward RCE. Fixed in 3.0.1.

`requests==2.31.0` is present as a negative control: it is not in the known-CVE
table, so it must not flag. Only an exactly pinned (`==`) vulnerable version is
flagged; an open range is left alone, so the false-positive rate stays near zero.

This fixture is what lifts the M-EVAL v2 external recall set past the framework
dependency gap it originally exposed (see `evaluation/external-recall.md`).
