"""AI-BOM export: the agentic stack as a CycloneDX 1.6 inventory.

Findings say what is *wrong*; the BOM says what is *there* - the inventory
artifact compliance and procurement ask for (EU AI Act supplier duties,
NIST AI RMF component inventory). Only the agent stack is exported - MCP
servers, subagents, A2A endpoints, instruction/prompt surfaces, agent
config; cloud resources belong in an infrastructure SBOM, not an AI-BOM.

Mapping (CycloneDX 1.6 JSON):

* stdio MCP servers and subagents -> ``components[]`` (type ``application``),
  with a purl when the launch pins an npm/PyPI package version
* instruction and prompt files    -> ``components[]`` (type ``data``)
* agent settings/hooks files      -> ``components[]`` (type ``file``)
* remote MCP servers, A2A cards   -> ``services[]`` (endpoints,
  ``authenticated``, ``x-trust-boundary``)
* the delegation / tool-access graph -> ``dependencies[]`` from the root

Attestral-specific facts (capability classes, canonical manifest hash,
source file) ride along as ``attestral:`` namespaced properties, so the BOM
carries the same identity the compiled runtime policy pins (DRF-005).
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

from attestral import __version__
from attestral.manifest import manifest_hash
from attestral.model import SystemModel

_SPEC_VERSION = "1.6"

_PKG_RE = re.compile(r"^(@?[\w./-]+)@(\d[\w.+-]*)$")
_NPM_RUNNERS = {"npx", "npm", "pnpm", "bunx"}
_PYPI_RUNNERS = {"uvx", "pipx", "uv"}


def _purl(command, args) -> str | None:
    """pkg:npm/... or pkg:pypi/... when the launch pins <package>@<version>.
    Only the first non-flag argument is considered - that is the package a
    runner executes; everything after it belongs to the server itself."""
    runner = str(command or "").rsplit("/", 1)[-1].lower()
    if runner in _NPM_RUNNERS:
        ptype = "npm"
    elif runner in _PYPI_RUNNERS:
        ptype = "pypi"
    else:
        return None
    for a in args or []:
        a = str(a)
        if a.startswith("-"):
            continue
        m = _PKG_RE.match(a)
        if m:
            name, version = m.groups()
            if name.startswith("@"):
                name = "%40" + name[1:]  # purl scope encoding
            return f"pkg:{ptype}/{name}@{version}"
        return None  # first real arg is not a pinned package
    return None


def _props(pairs) -> list[dict]:
    return [{"name": k, "value": str(v)} for k, v in pairs if v]


def build_aibom(model: SystemModel, target: str) -> dict:
    root_ref = "attestral:scan-target"
    components: list[dict] = []
    services: list[dict] = []
    depends: list[str] = []

    for c in model.components:
        if c.trust_boundary != "agent_runtime":
            continue  # cloud/cluster inventory belongs in an infra SBOM
        source_prop = ("attestral:source", c.source)
        if c.type == "mcp_server":
            url = str(c.attr("url") or "")
            props = _props([
                ("attestral:component-type", "mcp_server"),
                ("attestral:capabilities", ",".join(c.attr("_capabilities") or [])),
                ("attestral:manifest-sha256", manifest_hash(
                    c.attr("command") or "", c.attr("args") or [], url,
                    c.attr("_tool_descriptions") or [],
                )),
                source_prop,
            ])
            if url:
                services.append({
                    "bom-ref": c.id,
                    "name": c.name,
                    "endpoints": [url],
                    "authenticated": not c.attr("_remote_unauthed", False),
                    "x-trust-boundary": True,
                    "properties": props,
                })
            else:
                entry = {
                    "bom-ref": c.id, "type": "application",
                    "name": c.name, "properties": props,
                }
                purl = _purl(c.attr("command"), c.attr("args"))
                if purl:
                    entry["purl"] = purl
                components.append(entry)
        elif c.type == "subagent":
            tools = ",".join(c.attr("_tools") or [])
            components.append({
                "bom-ref": c.id, "type": "application", "name": c.name,
                "properties": _props([
                    ("attestral:component-type", "subagent"),
                    ("attestral:capabilities", ",".join(c.attr("_capabilities") or [])),
                    ("attestral:tools", tools),
                    ("attestral:inherits-all-tools",
                     "true" if c.attr("_wildcard_tools") else ""),
                    source_prop,
                ]),
            })
        elif c.type == "a2a_agent":
            url = str(c.attr("url") or "")
            entry = {
                "bom-ref": c.id, "name": c.name,
                "authenticated": not c.attr("_no_auth_declared", False),
                "x-trust-boundary": True,
                "properties": _props([
                    ("attestral:component-type", "a2a_agent"), source_prop,
                ]),
            }
            if url:
                entry["endpoints"] = [url]
            services.append(entry)
        elif c.type in ("agent_instruction", "system_prompt"):
            components.append({
                "bom-ref": c.id, "type": "data", "name": c.name,
                "properties": _props([
                    ("attestral:component-type", c.type), source_prop,
                ]),
            })
        elif c.type == "agent_config":
            components.append({
                "bom-ref": c.id, "type": "file", "name": c.name,
                "properties": _props([
                    ("attestral:component-type", "agent_config"), source_prop,
                ]),
            })
        else:
            continue
        depends.append(c.id)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {
                "components": [
                    {"type": "application", "name": "attestral", "version": __version__}
                ]
            },
            "component": {"bom-ref": root_ref, "type": "application", "name": target},
        },
        "components": components,
        "services": services,
        "dependencies": [{"ref": root_ref, "dependsOn": sorted(depends)}],
    }


def render_aibom(model: SystemModel, target: str) -> str:
    return json.dumps(build_aibom(model, target), indent=2) + "\n"
