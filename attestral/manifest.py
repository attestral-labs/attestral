"""Canonical MCP tool-manifest hashing (rug-pull detection).

The rug-pull attack: a tool server's surface - its tools, their descriptions,
or its launch identity - changes AFTER the design was reviewed, so the
reviewed tool is not the tool that runs. The defense is to pin what was
attested: hash the manifest canonically at scan time, carry the hash through
`compile` into the runtime policy, and have `drift` re-hash what actually
runs (DRF-005 on mismatch).

One canonicalization shared by both sides (ingest and drift), so a hash
computed from a config file and one computed from runtime telemetry are
comparable byte-for-byte.
"""
from __future__ import annotations

import hashlib
import json


def normalize_tools(tools) -> list[dict]:
    """Every declared tool as {name, description}, list- or dict-shaped input."""
    out: list[dict] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("name"):
                out.append(
                    {"name": str(t["name"]), "description": str(t.get("description", ""))}
                )
    elif isinstance(tools, dict):
        for name, t in tools.items():
            desc = t.get("description", "") if isinstance(t, dict) else (t or "")
            out.append({"name": str(name), "description": str(desc)})
    return out


def canonical_manifest(
    command: str = "", args: list | None = None, url: str = "", tools: list[dict] | None = None
) -> dict:
    """The manifest exactly as hashed: launch identity + name-sorted tool surface."""
    return {
        "command": str(command or ""),
        "args": [str(a) for a in (args or [])],
        "url": str(url or ""),
        "tools": sorted(
            (
                {"name": str(t.get("name", "")), "description": str(t.get("description", ""))}
                for t in (tools or [])
                if isinstance(t, dict)
            ),
            key=lambda t: t["name"],
        ),
    }


def manifest_hash(
    command: str = "", args: list | None = None, url: str = "", tools: list[dict] | None = None
) -> str:
    payload = json.dumps(
        canonical_manifest(command, args, url, tools), sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode()).hexdigest()
