"""MCP server configuration ingestion (claude_desktop_config.json / .mcp.json style)."""
from __future__ import annotations

import json
from pathlib import Path

from attestral.model import Component, SystemModel

_SECRET_HINTS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL")


def ingest_mcp(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    files = [p] if p.is_file() else sorted(
        list(p.rglob("*.mcp.json")) + list(p.rglob("mcp*.json")) + list(p.rglob("claude_desktop_config.json"))
    )
    for f in files:
        try:
            data = json.loads(f.read_text(errors="ignore"))
        except json.JSONDecodeError:
            continue
        servers = data.get("mcpServers") or data.get("servers") or {}
        for name, cfg in servers.items():
            attrs: dict = {}
            if isinstance(cfg, dict):
                attrs["command"] = cfg.get("command", "")
                attrs["args"] = cfg.get("args", [])
                attrs["url"] = cfg.get("url", "")
                env = cfg.get("env", {}) or {}
                attrs["env_keys"] = list(env.keys())
                attrs["_env_has_secrets"] = any(
                    any(h in k.upper() for h in _SECRET_HINTS) for k in env
                )
            model.add(
                Component(
                    id=f"mcp_server.{name}",
                    type="mcp_server",
                    name=name,
                    source=str(f),
                    attributes=attrs,
                    trust_boundary="agent_runtime",
                )
            )
    return model
