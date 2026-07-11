"""Attestral-format telemetry emitter for mcp-guard.

Drop-in module: emits one JSON object per tool-call decision, in exactly the
JSONL schema `attestral drift` consumes. Designed to be called from
mcp-guard's proxy layer after each allow/deny decision.

Schema (one line per event):
    {"ts": ISO-8601 UTC, "server": str, "tool": str,
     "args": list[str], "url": str | omitted, "decision": "allow"|"deny"}

Only `server` and `tool` are required by attestral; the rest enrich drift
findings. `decision` is recorded so denied-but-attempted calls still appear
in the drift analysis (a blocked attempt is still a signal the design and
reality disagree).
"""
from __future__ import annotations

import datetime as _dt
import json
import threading
from pathlib import Path


class TelemetryWriter:
    """Append-only, thread-safe JSONL writer with size-based rotation."""

    def __init__(self, path: str | Path, max_bytes: int = 50_000_000):
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def emit(
        self,
        server: str,
        tool: str,
        args: list | None = None,
        url: str = "",
        decision: str = "allow",
    ) -> None:
        event = {
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "server": server,
            "tool": tool,
            "args": [str(a) for a in (args or [])],
            "decision": decision,
        }
        if url:
            event["url"] = url
        line = json.dumps(event, separators=(",", ":")) + "\n"
        with self._lock:
            self._rotate_if_needed()
            with self.path.open("a") as f:
                f.write(line)

    def _rotate_if_needed(self) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                rotated = self.path.with_suffix(
                    "." + _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%S") + ".jsonl"
                )
                self.path.rename(rotated)
        except OSError:
            pass  # never let telemetry rotation break the proxy request path
