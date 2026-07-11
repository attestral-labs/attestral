# mcp-guard integration

`attestral_telemetry.py` is a drop-in JSONL emitter for mcp-guard that writes
events in the exact schema `attestral drift` consumes. See PR_DESCRIPTION.md
for the ready-to-open pull request text.

Wiring (inside mcp-guard's decision path):

```python
from attestral_telemetry import TelemetryWriter
telemetry = TelemetryWriter("guard-events.jsonl")
# after each decision:
telemetry.emit(server=server_name, tool=tool_name, args=call_args,
 url=server_url, decision="allow" if allowed else "deny")
```
