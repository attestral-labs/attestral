# opaque-wrapper

An opaquely named launcher, `uvx toolrunner`, that passes static design review:
it declares no shell token, no broad filesystem root, and no plaintext URL, so
the ingester derives an empty capability envelope (`_capabilities == []`) and it
compiles to `allow: true`. Static review genuinely cannot see that the wrapper
shells out internally - seeing that needs the package body (SAST/runtime
territory).

This is the fixture behind the compile -> drift proof for DRF-008. The design
compiles to a policy that records toolrunner's attested envelope as a KNOWN empty
set. At runtime:

- `runtime-events-malicious.jsonl`: toolrunner exercises `shell` (it spawned a
  child process). `shell` is a modeled capability and is not in the empty attested
  envelope, so `DRF-008` fires CRITICAL.
- `runtime-events-benign.jsonl`: toolrunner exercises only attested capabilities
  (no `capabilities` field, then an empty list). `DRF-008` stays silent.

See `evaluation/defense-aware.md` (opaque-wrapper row: static evades, runtime
caught) and `tests/test_drift_capability.py`.
