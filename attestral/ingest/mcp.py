"""MCP server configuration ingestion (claude_desktop_config.json / .mcp.json style)."""
from __future__ import annotations

import json
from pathlib import Path

from attestral.manifest import manifest_hash, normalize_tools
from attestral.model import Component, SystemModel

_SECRET_HINTS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL")

# Env keys that are specifically CLOUD credentials: unlike the generic
# _SECRET_HINTS, these prove a live path from the agent runtime into the
# cloud trust boundary (ATL-112 + a reachability edge in scan.py).
_CLOUD_CRED_HINTS = (
    "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AZURE_CLIENT", "AZURE_TENANT", "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_KEY", "GCP_SERVICE_ACCOUNT", "KUBECONFIG",
)

# Launch-command flags that hand an agent autonomy with no human checkpoint.
# Presence of any of these (or a non-empty client-side auto-approve list) means
# tool calls run end-to-end, so a single prompt injection executes uninterrupted.
_AUTO_APPROVE_FLAGS = (
    "--dangerously-skip-permissions", "--yolo", "--allow-all",
    "--auto-approve", "--yes-to-all", "--no-confirm",
)

# Exact launch tokens (compared by basename) that mean the server itself is a
# shell; substring hints would false-positive on words like "publish".
_SHELL_TOKENS = {"bash", "sh", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh"}

# Substring hints, matched against the launch command + server name, that
# classify what a tool server can reach. Deliberately coarse: they feed the
# fleet-level combination rules (ATL-202/203), not per-server findings, so a
# missed class costs one cross-cutting finding rather than a false alarm.
_CAPABILITY_HINTS = {
    "filesystem": ("server-filesystem", "filesystem", "file-system"),
    "network": ("server-fetch", "fetch", "puppeteer", "playwright", "browser",
                "scrape", "webcrawl", "http"),
    "messaging": ("slack", "gmail", "smtp", "sendgrid", "discord", "telegram", "twilio"),
    "database": ("postgres", "sqlite", "mysql", "mongodb", "redis", "supabase",
                 "snowflake", "bigquery"),
    "saas_data": ("github", "gitlab", "notion", "jira", "linear", "confluence",
                  "gdrive", "google-drive", "dropbox", "sharepoint", "salesforce"),
    # Persistent agent memory / vector stores: the target of memory-poisoning
    # (Kim et al. 2026, V6) and a source of private data the agent reads back
    # across sessions, so it also counts toward the exfiltration trifecta.
    "memory": ("mem0", "server-memory", "memory-server", "knowledge-graph",
               "chroma", "pinecone", "weaviate", "qdrant", "milvus", "vectorstore"),
}


def _tool_descriptions(tools) -> list[dict]:
    """Normalize a manifest's `tools` into [{name, description}] entries."""
    out: list[dict] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("description"):
                out.append(
                    {"name": str(t.get("name", "")), "description": str(t["description"])}
                )
    elif isinstance(tools, dict):
        for tname, t in tools.items():
            desc = t.get("description") if isinstance(t, dict) else t
            if desc:
                out.append({"name": str(tname), "description": str(desc)})
    return out


def _tool_names(tools) -> list[str]:
    """Every declared tool name, description or not — the fleet's tool
    namespace. Unlike _tool_descriptions (an ML scoring surface), a name
    matters even when bare: cross-server collisions key on the name alone."""
    names: list[str] = []
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("name"):
                names.append(str(t["name"]))
    elif isinstance(tools, dict):
        names.extend(str(k) for k in tools)
    return names


def component_from_server(name: str, cfg, source: str) -> Component:
    """Build the mcp_server component (with every derived _attr) for one
    config entry. Shared by repo scans here and by scan --local, which also
    pulls servers out of places ingest_mcp's globs never see (e.g. the
    project scopes nested inside Claude Code's ~/.claude.json)."""
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
        # Excessive agency (OWASP LLM06): a server wired to run tools
        # with no human checkpoint - via an explicit auto-approve /
        # allow list in the client config, or an autonomy flag on the
        # launch command. Derived here so rules stay simple attr checks.
        launch = " ".join(
            [str(attrs["command"])] + [str(a) for a in attrs["args"] or []]
        )
        auto_list = (
            cfg.get("autoApprove") or cfg.get("alwaysAllow")
            or cfg.get("auto_approve")
        )
        attrs["_auto_approve"] = bool(auto_list) or any(
            flag in launch for flag in _AUTO_APPROVE_FLAGS
        )
        # Remote transport (a `url`) with no declared authentication:
        # anyone who can reach the endpoint can drive the tool server, or
        # impersonate it to the agent. A secret env var or an auth header
        # counts as "authenticated"; only set on remote servers so the
        # rule (attr_equals _remote_unauthed=true) never matches stdio.
        if attrs["url"]:
            headers = cfg.get("headers")
            header_keys = (
                [str(k).lower() for k in headers]
                if isinstance(headers, dict) else []
            )
            has_auth = (
                bool(cfg.get("auth"))
                or attrs["_env_has_secrets"]
                or any(
                    "authorization" in k or "api-key" in k
                    or "apikey" in k or "token" in k
                    for k in header_keys
                )
            )
            attrs["_remote_unauthed"] = not has_auth
            # Confused-deputy / token passthrough (MCP Security Best Practices
            # 2025-06-18): a network-reachable server that ALSO holds a
            # downstream credential can be induced to spend that delegated
            # authority on an attacker's behalf. The downstream credential is a
            # secret the SERVER PROCESS holds (in env) - NOT an auth header,
            # which is the client's inbound credential to reach this endpoint
            # (ATL-109's own remediation) and must never trip a deputy finding.
            attrs["_confused_deputy"] = bool(attrs["_env_has_secrets"])
        # Coarse capability classes for the model-level combination
        # rules. The risk they capture is fleet-level: no single server
        # is the finding - private data + an outbound channel is an
        # exfiltration chain, shell + an outbound channel is C2.
        caps: set[str] = set()
        tokens = {Path(t).name.lower() for t in launch.split()}
        if tokens & _SHELL_TOKENS:
            caps.add("shell")
        surface = f"{launch} {name}".lower()
        for cap, hints in _CAPABILITY_HINTS.items():
            if any(h in surface for h in hints):
                caps.add(cap)
        attrs["_capabilities"] = sorted(caps)
        # Natural-language surfaces (server + tool descriptions) are
        # kept for the optional ML layer to score for injection text.
        if cfg.get("description"):
            attrs["description"] = str(cfg["description"])
        tool_descs = _tool_descriptions(cfg.get("tools"))
        if tool_descs:
            attrs["_tool_descriptions"] = tool_descs
        tool_names = _tool_names(cfg.get("tools"))
        if tool_names:
            attrs["_tool_names"] = tool_names
        # Rug-pull pin: canonical hash of the launch identity + tool surface.
        # compile carries it into the policy; drift re-hashes at runtime.
        attrs["_manifest_hash"] = manifest_hash(
            attrs["command"], attrs["args"], attrs["url"], normalize_tools(cfg.get("tools"))
        )
        # Cloud credentials are a provable agent->cloud crossing, stronger
        # than the generic secret hint above.
        cred_keys = [
            k for k in attrs["env_keys"]
            if any(h in k.upper() for h in _CLOUD_CRED_HINTS)
        ]
        attrs["_cloud_credential_keys"] = cred_keys
        attrs["_has_cloud_credentials"] = bool(cred_keys)
    return Component(
        id=f"mcp_server.{name}",
        type="mcp_server",
        name=name,
        source=source,
        attributes=attrs,
        trust_boundary="agent_runtime",
    )


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
            model.add(component_from_server(name, cfg, str(f)))
    return model
