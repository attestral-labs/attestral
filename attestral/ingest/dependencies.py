"""Ingest an agent's declared dependencies and flag known-vulnerable versions.

The design-time model already flags an MCP *server* pinned to a known-vulnerable
package (ATL-117, over the launch command). This does the same for the agent's
own dependency tree - the Python / JS libraries it is built on - which the MCP
ingester never sees. It is the surface behind a whole class of real 2025-2026
advisories (LangGrinch CVE-2025-68664, the langgraph chain) that a config review
misses because the vulnerability lives in a `requirements.txt`, not an mcp.json.

Kept in the same spirit as the MCP known-CVE table: a small, curated, high-signal
list of advisories with exact affected version ranges, matched only against an
EXACTLY pinned version (`==` / an exact npm pin). A dependency pinned to a safe
version, or specified as an open range, is not flagged - we only fire on a
concrete, comparably-vulnerable pin, so the false-positive rate stays near zero.
Extend the table as advisories land (the weekly research radar is a feeder).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from attestral.model import Component, SystemModel

# (canonical package name, ((low_inclusive, high_inclusive), ...), CVE). A pinned
# version is vulnerable if it falls in ANY range - so a library patched on two
# branches (e.g. langchain-core 0.3.81 and 1.2.5) is expressed precisely, without
# false-flagging a fixed version on the other branch.
_KNOWN_DEP_VULNS = (
    # CVE-2025-68664 "LangGrinch": serialization 'lc' marker injection in
    # langchain-core exfiltrates env secrets (CVSS 9.3). Patched in 0.3.81 (0.x
    # branch) and 1.2.5 (1.x branch).
    ("langchain-core", (((0, 0, 0), (0, 3, 80)), ((1, 0, 0), (1, 2, 4))), "CVE-2025-68664"),
    # CVE-2026-34070: path traversal in langchain-core's prompt loading (CVSS
    # 7.5). Patched in 1.2.22.
    ("langchain-core", (((1, 0, 0), (1, 2, 21)),), "CVE-2026-34070"),
    # CVE-2025-67644: SQL injection in the langgraph SQLite checkpointer (CVSS
    # 7.3), chainable toward RCE. Patched in langgraph-checkpoint-sqlite 3.0.1.
    ("langgraph-checkpoint-sqlite", (((0, 0, 0), (3, 0, 0)),), "CVE-2025-67644"),
    # CVE-2026-28277: unsafe msgpack deserialization -> RCE when langgraph loads a
    # forged checkpoint (CVSS 6.8), chains with CVE-2025-67644. Patched in 1.0.10.
    ("langgraph", (((0, 0, 0), (1, 0, 9)),), "CVE-2026-28277"),
    # CVE-2026-27022: RediSearch query injection -> access-control bypass in the
    # langgraph Redis checkpointer (CVSS 6.5). Patched in 1.0.1. (npm, scoped.)
    ("@langchain/langgraph-checkpoint-redis", (((0, 0, 0), (1, 0, 0)),), "CVE-2026-27022"),
    # CVE-2026-0621: ReDoS in the MCP TypeScript SDK's UriTemplate parser (CVSS
    # 8.7). Affected >=1.3.0 <1.25.2; patched in 1.25.2. (npm, scoped.)
    ("@modelcontextprotocol/sdk", (((1, 3, 0), (1, 25, 1)),), "CVE-2026-0621"),
)

_MANIFESTS = ("requirements.txt", "pyproject.toml", "package.json")
# requirements line: `name[extras] == version` (only an exact pin is comparable).
_REQ_PIN = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*===?\s*([0-9][^\s;,#]*)")
# pyproject / PEP 621: a "name==version" dependency string.
_TOML_PIN = re.compile(r"""["']([A-Za-z0-9._-]+)\s*===?\s*([0-9][^"',\s]*)["']""")


def _canon(name: str) -> str:
    """PEP 503 normalization: runs of -_. collapse to '-', lowercased."""
    return re.sub(r"[-_.]+", "-", name).strip().lower()


def _version_tuple(v: str) -> tuple[int, ...]:
    out = []
    for part in v.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out) or (0,)


def _dep_cve(name: str, ver: str) -> str | None:
    """Return a CVE id if `name`==`ver` is a known-vulnerable pin, else None."""
    if not ver or not ver[0].isdigit():
        return None
    canon = _canon(name)
    vt = _version_tuple(ver)
    for pkg, ranges, cve in _KNOWN_DEP_VULNS:
        if canon != pkg:
            continue
        if any(_version_tuple_le(low, vt) and _version_tuple_le(vt, high) for low, high in ranges):
            return cve
    return None


def _version_tuple_le(a: tuple[int, ...], b: tuple[int, ...]) -> bool:
    return tuple(a) <= tuple(b)


def _parse_requirements(text: str) -> list[tuple[str, str]]:
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        if not line.strip() or line.lstrip().startswith("-"):
            continue
        m = _REQ_PIN.match(line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_pyproject(text: str) -> list[tuple[str, str]]:
    # Best-effort and dependency-free: match "name==version" dependency strings
    # (PEP 621 dependencies arrays and poetry "==" pins). Non-exact specs
    # (caret/tilde/ranges) are intentionally not matched.
    return [(m.group(1), m.group(2)) for m in _TOML_PIN.finditer(text)]


def _parse_package_json(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return []
    out = []
    for key in ("dependencies", "devDependencies"):
        for name, spec in (data.get(key) or {}).items():
            if isinstance(spec, str) and spec[:1].isdigit():  # exact npm pin only
                out.append((name, spec))
    return out


_PARSERS = {
    "requirements.txt": _parse_requirements,
    "pyproject.toml": _parse_pyproject,
    "package.json": _parse_package_json,
}


def ingest_dependencies(path: str | Path, model: SystemModel) -> SystemModel:
    """Emit a `dependency` component for each known-vulnerable pinned dependency."""
    p = Path(path)
    if p.is_file():
        files = [p] if p.name in _MANIFESTS else []
    else:
        files = sorted(f for name in _MANIFESTS for f in p.rglob(name))

    seen: set[str] = set()
    for f in files:
        parser = _PARSERS.get(f.name)
        if parser is None:
            continue
        try:
            deps = parser(f.read_text(errors="ignore"))
        except OSError:
            continue
        for name, ver in deps:
            cve = _dep_cve(name, ver)
            if not cve:
                continue
            canon = _canon(name)
            key = f"{canon}@{ver}:{cve}"
            if key in seen:
                continue
            seen.add(key)
            model.add(Component(
                id=f"dependency.{canon}",
                type="dependency",
                name=canon,
                source=str(f),
                attributes={
                    "name": canon, "version": ver,
                    "_has_known_cve": True, "_known_cve": cve,
                },
                trust_boundary="agent_runtime",
            ))
    return model
