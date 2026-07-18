"""Canonical MCP tool-manifest hashing (rug-pull and schema-poisoning detection).

The rug-pull attack: a tool server's surface - its tools, their descriptions,
their input schemas, or its launch identity - changes AFTER the design was
reviewed, so the reviewed tool is not the tool that runs. The nastiest variant
is schema poisoning: a tool's input schema gains a hidden parameter or an
instruction-bearing field description after approval, invisible to a single
design-time snapshot. The defense is to pin what was attested: hash the
manifest canonically at scan time, carry the hash through `compile` into the
runtime policy, and have `drift` re-hash what actually runs (DRF-005 on
mismatch).

The pinned tool surface is each tool's name, description, AND input schema, so
a silently changed schema flips the hash the same way a changed description
does. The schema is pinned structurally (object keys are canonicalized; any
other change, including a reordered array, is treated as a change) - a
fail-closed choice, since for a rug-pull detector any drift from the reviewed
schema is what we want to catch.

One canonicalization shared by both sides (ingest and drift), so a hash
computed from a config file and one computed from runtime telemetry are
comparable byte-for-byte.
"""
from __future__ import annotations

import hashlib
import json

# Keys an MCP tool may carry its JSON input schema under. `inputSchema` is the
# MCP spec's camelCase form; the others are common framework variants. First
# present, non-empty one wins.
_SCHEMA_KEYS = ("inputSchema", "input_schema", "parameters")


def _tool_schema(t: dict):
    """The tool's declared input schema, or None if it declares none. Only a
    non-empty value is pinned, so a schema-less tool's hash is unchanged from
    before schemas were pinned."""
    for key in _SCHEMA_KEYS:
        schema = t.get(key)
        if schema:
            return schema
    return None


def _normalized_tool(name: str, description, schema) -> dict:
    """One tool in canonical form: name + description always, input_schema only
    when the tool declares one (so schema-less tools keep their prior hash)."""
    tool = {"name": str(name), "description": str(description or "")}
    if schema is not None:
        tool["input_schema"] = schema
    return tool


def normalize_tools(tools) -> list[dict]:
    """Every declared tool as {name, description, input_schema?}, list- or
    dict-shaped input. input_schema is present only when the tool declares one."""
    out: list[dict] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("name"):
                out.append(_normalized_tool(t["name"], t.get("description"), _tool_schema(t)))
    elif isinstance(tools, dict):
        for name, t in tools.items():
            if isinstance(t, dict):
                out.append(_normalized_tool(name, t.get("description"), _tool_schema(t)))
            else:
                out.append(_normalized_tool(name, t or "", None))
    return out


def canonical_manifest(
    command: str = "", args: list | None = None, url: str = "", tools: list[dict] | None = None
) -> dict:
    """The manifest exactly as hashed: launch identity + name-sorted tool surface
    (each tool's name, description, and input schema when declared)."""
    return {
        "command": str(command or ""),
        "args": [str(a) for a in (args or [])],
        "url": str(url or ""),
        "tools": sorted(
            (
                _normalized_tool(t.get("name", ""), t.get("description"), _tool_schema(t))
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
