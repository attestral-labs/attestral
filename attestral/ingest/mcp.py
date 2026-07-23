"""MCP server configuration ingestion (claude_desktop_config.json / .mcp.json style)."""
from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from attestral.ingest import _jsonc
from attestral.manifest import manifest_hash, normalize_tools
from attestral.model import Component, SystemModel

_SECRET_HINTS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL")

# Header keys (lowercased, substring) that carry a credential to a remote MCP
# endpoint. Used twice, with opposite polarity: ANY of these counts as "the
# remote is authenticated" (clears ATL-109), while one holding a LITERAL value
# in a committed config is a hardcoded credential (ATL-157). Env indirection
# (`${VAR}` / `$VAR`) is the correct pattern and never counts as literal, and
# obvious placeholders (`<token>`, `REDACTED`, `changeme`, ...) fail closed so
# a sanitized example config is never flagged.
_AUTH_HEADER_HINTS = ("authorization", "api-key", "apikey", "token", "secret", "auth")
_HEADER_PLACEHOLDER_PREFIXES = (
    "<", "...", "your", "xxx", "changeme", "change-me", "change_me",
    "redacted", "todo", "tbd", "replace", "placeholder", "example",
)


def _literal_auth_header_value(value) -> bool:
    """True iff a header value is a concrete committed credential: a non-empty
    string with no env indirection and no placeholder shape."""
    if not isinstance(value, str):
        return False
    v = value.strip()
    if not v or "$" in v:  # ${VAR} / $VAR: resolved from the environment
        return False
    v_l = v.lower()
    for scheme in ("bearer ", "basic ", "token "):
        if v_l.startswith(scheme):
            v_l = v_l[len(scheme):].strip()
    if not v_l or v_l.startswith(_HEADER_PLACEHOLDER_PREFIXES):
        return False
    return True

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

# An egress-capable server whose launch or env constrains outbound reach to an
# allowlist of destinations is the declassifier ATL-202 recommends: data can only
# leave to known hosts, so it breaks the confidentiality half of an information-
# flow violation (ATL-217 clears while the coarse ATL-202/207 still fire). Matched
# conservatively - a bare "--allow" is too generic and would over-clear, so only
# an egress-scoped allowlist token counts.
_EGRESS_ALLOWLIST_HINTS = (
    "--allowed-hosts", "--allow-host", "--allowed-domains", "--allowed-origins",
    "--allowlist-hosts", "--allowlist-domains", "--url-allowlist",
    "allowed_hosts", "allowed_domains", "allowedhosts", "alloweddomains",
    "allowed-origins", "url_allowlist", "allowlisted_hosts",
)

# An explicit human-approval requirement on a shell/exec server is the endorser
# ATL-203/207 recommend: an injected command cannot run uninterrupted because a
# human must approve it, so it breaks the integrity half of an information-flow
# violation (ATL-217 clears while ATL-203/207 still fire). The positive inverse
# of _AUTO_APPROVE_FLAGS, matched conservatively - only an explicit approval
# token counts, so absence never fabricates an endorser.
_APPROVAL_HINTS = (
    "--require-approval", "--requires-approval", "--approval-required",
    "--require-confirmation", "--confirm", "--human-approval",
    "--human-in-the-loop", "--ask-approval",
    "requireapproval", "requiresapproval", "humanintheloop",
    "require_approval", "approval_required", "human_in_the_loop",
)

# Exact launch tokens (compared by basename) that mean the server itself is a
# shell; substring hints would false-positive on words like "publish".
_SHELL_TOKENS = {"bash", "sh", "zsh", "dash", "cmd", "cmd.exe", "powershell", "pwsh"}

# A shell hidden behind an interpreter: `node -e "require('child_process').exec(...)"`
# is shell-capable, but declares no shell token, so it evades the plain-token check
# (the defense-aware eval, M10, showed this). Detected when an interpreter is
# launched with an inline-eval flag AND its inline code contains a process-spawn
# call. Gated on the spawn marker so a benign `python -c "print(1)"` never fires.
_INTERPRETERS = {"node", "nodejs", "deno", "bun", "python", "python2", "python3",
                 "ruby", "perl", "php", "osascript"}
_INLINE_EVAL_FLAGS = {"-e", "-c", "--eval", "--exec", "-E", "-r"}
_SHELLOUT_MARKERS = (
    "child_process", "execsync", "spawnsync", "spawn(", ".exec(", "exec(",
    "os.system", "subprocess", "popen", "shell_exec", "system(", "`", "$(",
    "kernel.system", "io.popen", "commandline",
)


def _interpreter_shellout(command: str, args: list) -> bool:
    """True if the launch is an interpreter running inline code that spawns a
    process - a shell capability disguised as an ordinary interpreter call."""
    if Path(str(command)).name.lower() not in _INTERPRETERS:
        return False
    argv = [str(a) for a in (args or [])]
    if not any(a in _INLINE_EVAL_FLAGS for a in argv):
        return False
    code = " ".join(argv).lower()
    return any(m in code for m in _SHELLOUT_MARKERS)

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
               "chroma", "pinecone", "weaviate", "qdrant", "milvus", "vectorstore",
               "pgvector", "faiss"),
}

# Embedded advisory DB: MCP packages with a KNOWN CVE, and the inclusive maximum
# vulnerable version. A server launched with `<pkg>@<version>` at or below the
# affected ceiling is flagged (ATL-117). Kept intentionally small and curated -
# high-signal known-bad, not a full SCA feed. Extend as advisories land.
_KNOWN_VULNS = (
    # CVE-2025-6514: OS command injection -> RCE in mcp-remote when connecting to
    # an untrusted remote MCP server. Affected 0.0.5 through 0.1.15.
    ("mcp-remote", (0, 1, 15), "CVE-2025-6514"),
    # CVE-2026-50143: URL-authority injection in @apify/actors-mcp-server - a
    # standby-Actor URL is built from an attacker-controlled path, and the
    # client attaches the Apify bearer token to whatever host that resolves
    # to. Affected through 0.10.10; fixed in 0.10.11.
    ("actors-mcp-server", (0, 10, 10), "CVE-2026-50143"),
    # CVE-2025-53107: command injection -> RCE in @cyanheads/git-mcp-server;
    # gitAdd/gitCheckout built shell commands via child_process.exec without
    # sanitizing input. Affected through 2.1.4; fixed in 2.1.5.
    ("git-mcp-server", (2, 1, 4), "CVE-2025-53107"),
    # CVE-2026-27826: unauthenticated SSRF (credential theft + prompt injection)
    # in mcp-atlassian via unvalidated X-Atlassian-Jira-Url/Confluence-Url
    # headers. Affected below 0.17.0; fixed in 0.17.0.
    ("mcp-atlassian", (0, 16, 9999), "CVE-2026-27826"),
    # CVE-2026-35394: intent injection in @mobilenext/mobile-mcp - the
    # mobile_open_url tool passed URLs to Android's intent system with no
    # scheme validation, allowing arbitrary intents (calls, SMS, USSD, content
    # providers). Affected below 0.0.50; fixed in 0.0.50 (scheme allowlist).
    ("mobile-mcp", (0, 0, 49), "CVE-2026-35394"),
)


def _version_tuple(v: str) -> tuple[int, ...]:
    """Best-effort numeric version tuple ('0.1.15' -> (0,1,15)); non-numeric
    components collapse to 0 so a comparison never raises."""
    out = []
    for part in v.split("."):
        digits = "".join(ch for ch in part if ch.isdigit())
        out.append(int(digits) if digits else 0)
    return tuple(out) or (0,)


def _known_cve(tokens: list[str]) -> str | None:
    """Return a CVE id if any `<pkg>@<version>` launch token names a known-
    vulnerable MCP package at or below its affected ceiling, else None. A
    server pinned to a safe version, or unpinned (that is ATL-106's job), is
    not flagged - we only fire on a concrete, comparably-vulnerable version."""
    for tok in tokens:
        if "@" not in tok:
            continue
        name, _, ver = tok.rpartition("@")
        name = name.split("/")[-1]  # strip an npm scope like @scope/pkg
        if not ver or not ver[0].isdigit():
            continue  # e.g. "@latest" / "@beta": no comparable version
        for pkg, ceiling, cve in _KNOWN_VULNS:
            if name == pkg and _version_tuple(ver) <= ceiling:
                return cve
    return None


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


# Keys a tool may carry its JSON input schema under (mirrors manifest._SCHEMA_KEYS).
_TOOL_SCHEMA_KEYS = ("inputSchema", "input_schema", "parameters")
_REMOTE_REF_PREFIXES = ("http://", "https://", "ftp://", "file://", "//")


def _external_schema_refs(tools) -> list[str]:
    """Every external `$ref` target in any tool's input schema. Full JSON Schema
    2020-12 in tool parameters (MCP spec RC 2026-07-28, SEP-2106) lets a schema
    `$ref` point to a remote URL; a client that auto-dereferences it fetches
    attacker-controlled schema (poisoning) or is steered to an internal URL
    (SSRF). A local `#/...` fragment ref is normal and never flagged."""
    refs: list[str] = []

    def _walk(node) -> None:
        if isinstance(node, dict):
            r = node.get("$ref")
            if isinstance(r, str) and r.strip().lower().startswith(_REMOTE_REF_PREFIXES):
                refs.append(r.strip())
            for v in node.values():
                _walk(v)
        elif isinstance(node, list):
            for v in node:
                _walk(v)

    items = tools if isinstance(tools, list) else (
        list(tools.values()) if isinstance(tools, dict) else [])
    for t in items:
        if isinstance(t, dict):
            for k in _TOOL_SCHEMA_KEYS:
                _walk(t.get(k))
    return refs


def _header_mapped_params(tools) -> list[str]:
    """Every tool parameter mapped into a transport HTTP header via the
    `x-mcp-header` schema extension (MCP SEP-2243, Final). The client mirrors
    the model-chosen argument value into an `Mcp-Param-{Name}` header that load
    balancers, WAFs, rate limiters, and authorization gateways act on - so a
    mapped parameter is model-controlled input flowing straight into transport
    policy decisions (ATL-158). Entries read "tool.param -> Mcp-Param-Name".
    Only a string-valued `x-mcp-header` counts (the SEP requires it); anything
    else is ignored, never guessed."""
    out: list[str] = []

    def _walk(node, tname: str) -> None:
        if isinstance(node, dict):
            props = node.get("properties")
            if isinstance(props, dict):
                for pname, pschema in props.items():
                    if isinstance(pschema, dict) and isinstance(pschema.get("x-mcp-header"), str):
                        out.append(f"{tname}.{pname} -> Mcp-Param-{pschema['x-mcp-header']}")
            for v in node.values():
                _walk(v, tname)
        elif isinstance(node, list):
            for v in node:
                _walk(v, tname)

    if isinstance(tools, list):
        items = [(str(t.get("name", "tool")), t) for t in tools if isinstance(t, dict)]
    elif isinstance(tools, dict):
        items = [(str(k), t) for k, t in tools.items() if isinstance(t, dict)]
    else:
        items = []
    for tname, t in items:
        for k in _TOOL_SCHEMA_KEYS:
            _walk(t.get(k), tname)
    return out


def _tool_names(tools) -> list[str]:
    """Every declared tool name, description or not - the fleet's tool
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
        # Remote transport (a `url`) that is genuinely exposed: a non-loopback,
        # PLAINTEXT http endpoint with no declared authentication. A secret env
        # var or an auth header counts as "authenticated"; only set on remote
        # servers so the rule (attr_equals _remote_unauthed=true) never matches
        # stdio.
        #
        # OAuth-per-spec awareness (MCP Security Best Practices, spec revisions
        # 2025-06-18 and 2025-11-25): the HTTP transports mandate OAuth 2.1, and
        # the client obtains that token through an interactive flow at connect
        # time - so a spec-compliant https:// (or wss://) endpoint carries NO
        # static credential in this config, and that absence is expected, not a
        # finding. Flagging it would false-positive on every OAuth-gated hosted
        # server (github, supabase, sentry, ...). We flag ONLY a plaintext,
        # non-loopback http endpoint: it is reachable by anyone on the path and,
        # even if it did negotiate OAuth, the bearer token would cross the wire
        # in cleartext. A loopback dev endpoint is not exposed, so it is exempt.
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
            url_l = attrs["url"].strip().lower()
            is_plaintext = url_l.startswith("http://")
            is_loopback = any(
                h in url_l for h in ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")
            )
            attrs["_remote_unauthed"] = (
                not has_auth and is_plaintext and not is_loopback
            )
            # Confused-deputy / token passthrough (MCP Security Best Practices
            # 2025-06-18): a network-reachable server that ALSO holds a
            # downstream credential can be induced to spend that delegated
            # authority on an attacker's behalf. The downstream credential is a
            # secret the SERVER PROCESS holds (in env) - NOT an auth header,
            # which is the client's inbound credential to reach this endpoint
            # (ATL-109's own remediation) and must never trip a deputy finding.
            attrs["_confused_deputy"] = bool(attrs["_env_has_secrets"])
            # Hardcoded inbound credential (ATL-157): an auth-shaped header
            # whose value is a LITERAL committed token rather than `${ENV}`
            # indirection. Deliberately distinct from ATL-109: the endpoint IS
            # authenticated (this header clears _remote_unauthed above, and
            # OAuth-per-spec endpoints carry no header at all) - the finding
            # is that the credential itself now lives in version control.
            static_auth = sorted(
                str(k)
                for k, v in (headers.items() if isinstance(headers, dict) else [])
                if any(h in str(k).lower() for h in _AUTH_HEADER_HINTS)
                and _literal_auth_header_value(v)
            )
            if static_auth:
                attrs["_static_auth_header_keys"] = static_auth
                attrs["_has_static_auth_header"] = True
        # Coarse capability classes for the model-level combination
        # rules. The risk they capture is fleet-level: no single server
        # is the finding - private data + an outbound channel is an
        # exfiltration chain, shell + an outbound channel is C2.
        caps: set[str] = set()
        tokens = {Path(t).name.lower() for t in launch.split()}
        interp_shell = _interpreter_shellout(attrs.get("command", ""), attrs.get("args") or [])
        attrs["_shell_via_interpreter"] = interp_shell
        if tokens & _SHELL_TOKENS or interp_shell:
            caps.add("shell")
        surface = f"{launch} {name}".lower()
        for cap, hints in _CAPABILITY_HINTS.items():
            if any(h in surface for h in hints):
                caps.add(cap)
        attrs["_capabilities"] = sorted(caps)
        # Egress allowlist (the declassifier ATL-202 recommends): only meaningful
        # on an egress-capable server, matched against the launch command and the
        # env keys/values so an allowlist set either way is seen.
        if caps & {"network", "messaging"}:
            egress_surface = " ".join(
                [launch] + [str(k) for k in env] + [str(v) for v in env.values()]
            ).lower()
            if any(h in egress_surface for h in _EGRESS_ALLOWLIST_HINTS):
                attrs["_egress_allowlisted"] = True
        # Human-approval gate on a shell sink (the integrity endorser): only
        # meaningful on an execution-capable server, matched against launch + env.
        if "shell" in caps:
            approval_surface = " ".join(
                [launch] + [str(k) for k in env] + [str(v) for v in env.values()]
            ).lower()
            if any(h in approval_surface for h in _APPROVAL_HINTS):
                attrs["_requires_approval"] = True
        # Protocol-level capabilities the server DECLARES it supports
        # (`capabilities: {sampling: {}, elicitation: {}}` or a list). Distinct
        # from the coarse reachability classes above: `sampling` lets a server
        # spend the user's model tokens and steer tool calls, `elicitation` lets
        # it prompt the user for extra input - both server-initiated channels
        # abused for token drain, covert tool invocation, and deceptive
        # data-gathering (Unit 42, 2025-12; "When MCP Servers Attack", 2025-09).
        # Only set when the config actually declares them, so absence never fires.
        declared = cfg.get("capabilities")
        if isinstance(declared, dict):
            caps_declared = sorted(str(k) for k, v in declared.items() if v is not False)
        elif isinstance(declared, list):
            caps_declared = sorted(str(c) for c in declared)
        else:
            caps_declared = []
        if caps_declared:
            attrs["_declared_capabilities"] = caps_declared
        # Identity-propagation gap: a data-access server (database / memory /
        # saas_data) whose env holds a secret reaches the store through ONE
        # static service identity, so every agent caller looks the same
        # downstream and per-user entitlements cannot be enforced there.
        # Feeds the model-level shared-identity rule (with an exposed A2A
        # endpoint as the multi-caller side). Set only when true, like
        # _confused_deputy above.
        if attrs["_env_has_secrets"] and caps & {"database", "memory", "saas_data"}:
            attrs["_shared_static_credential"] = True
        # Vector / memory store reached through one static credential: every
        # user's embedded data lands in one store behind one key, so a query
        # can retrieve any tenant's vectors (OWASP LLM08 cross-tenant leakage).
        # Narrower than _shared_static_credential (memory only) and, unlike the
        # model-level shared-identity rule, it needs no public endpoint - the
        # isolation gap exists for a purely internal multi-user agent too.
        if attrs["_env_has_secrets"] and "memory" in caps:
            attrs["_shared_memory_credential"] = True
        # Known-CVE supply-chain check (ATL-117): does the launch pin a package
        # version with a published advisory?
        cve = _known_cve(launch.split())
        attrs["_known_cve"] = cve or ""
        attrs["_has_known_cve"] = bool(cve)
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
        ext_refs = _external_schema_refs(cfg.get("tools"))
        if ext_refs:
            attrs["_tool_schema_external_ref"] = True
            attrs["_external_schema_ref_urls"] = ext_refs
        header_params = _header_mapped_params(cfg.get("tools"))
        if header_params:
            attrs["_header_mapped_params"] = header_params
            attrs["_has_header_mapped_params"] = True
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
            data = _jsonc.loads(f.read_text(errors="ignore"))
        except json.JSONDecodeError:
            continue
        servers = data.get("mcpServers") or data.get("servers") or {}
        for name, cfg in servers.items():
            model.add(component_from_server(name, cfg, str(f)))
    return model


# --- MCP Registry server.json manifest -------------------------------------
# The official registry (registry.modelcontextprotocol.io) publishes each server
# as a `server.json` (schema 2025-12-11): a reverse-DNS name, declared packages
# with `environmentVariables` and remote `headers` carrying `isSecret` flags, and
# transports. It is a distinct design-time surface from a client mcp.json: it
# describes what a PUBLISHED server declares, so it is where secret-handling
# mistakes (a secret not flagged, a credential baked in) and deprecated
# transports are statically visible before install.

_REGISTRY_SCHEMA_HINT = "modelcontextprotocol"

# Transports the MCP spec has retired. HTTP+SSE was deprecated (SEP-2596) in
# favour of streamable-http; the early WebSocket transport was dropped for its
# weak origin validation (CVE-2026-59950). A manifest still advertising either
# strands current-spec clients and keeps the server on an unmaintained, weaker
# channel. Compared against the lowercased registry transport type, exact token.
_DEPRECATED_TRANSPORTS = ("sse", "websocket", "ws")


def _is_secret_named(name: str) -> bool:
    return any(h in name.upper() for h in _SECRET_HINTS)


def _registry_vars(manifest: dict) -> list[dict]:
    """Flatten the manifest's declared secret/config surfaces - package env vars
    and remote headers - each as {name, is_secret, has_value}."""
    out: list[dict] = []
    sources: list = []
    for pkg in manifest.get("packages") or []:
        if isinstance(pkg, dict):
            sources.append(pkg.get("environmentVariables"))
    for remote in manifest.get("remotes") or []:
        if isinstance(remote, dict):
            sources.append(remote.get("headers"))
    for entries in sources:
        if not isinstance(entries, list):
            continue
        for e in entries:
            if isinstance(e, dict) and e.get("name"):
                out.append({
                    "name": str(e["name"]),
                    "is_secret": e.get("isSecret") is True,
                    "has_value": bool(e.get("value")),
                })
    return out


def _registry_transports(manifest: dict) -> list[str]:
    out: list[str] = []
    for pkg in manifest.get("packages") or []:
        t = pkg.get("transport") if isinstance(pkg, dict) else None
        if isinstance(t, dict) and t.get("type"):
            out.append(str(t["type"]).lower())
    for remote in manifest.get("remotes") or []:
        if isinstance(remote, dict) and remote.get("type"):
            out.append(str(remote["type"]).lower())
    return out


# Namespace-vs-source mismatch (ATL-159). The registry's namespace-verification
# model ties a reverse-DNS name to proof of ownership: `com.example/*` may only
# be published by whoever passes a DNS/HTTP challenge on example.com, while
# `io.github.*` is verified by GitHub login. A manifest consumed OUTSIDE the
# official registry (vendored, mirrored, self-hosted) never went through that
# check, so a name squatting a domain the publisher does not control is
# statically visible when neither the repository nor any remote lives anywhere
# near the claimed domain. Forge namespaces are account-verified, not
# domain-verified - a remote on any host is consistent with them - so they are
# skipped entirely; and a forge-hosted repository whose OWNER matches the
# domain's registrable label (com.example + github.com/example, the normal
# open-source layout) counts as matching. Fail-closed: no derivable domain or
# no comparable source URL derives nothing.
_FORGE_NAMESPACE_PREFIXES = ("io.github.", "com.github.", "io.gitlab.", "com.gitlab.")
_FORGE_REPO_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")


def _namespace_domain(name: str) -> str:
    """The DNS domain a reverse-DNS registry name claims ('com.example/x' ->
    'example.com'), or '' when it is not domain-based (a forge namespace, or
    no dot-separated prefix)."""
    prefix = str(name).split("/")[0].strip().lower()
    if not prefix or "." not in prefix:
        return ""
    if prefix.startswith(_FORGE_NAMESPACE_PREFIXES):
        return ""
    return ".".join(reversed(prefix.split(".")))


def _manifest_source_urls(manifest: dict) -> list[str]:
    """The manifest's declared source URLs: repository.url plus remotes[].url."""
    urls: list[str] = []
    repo = manifest.get("repository")
    if isinstance(repo, dict) and repo.get("url"):
        urls.append(str(repo["url"]))
    elif isinstance(repo, str) and repo:
        urls.append(repo)
    for remote in manifest.get("remotes") or []:
        if isinstance(remote, dict) and remote.get("url"):
            urls.append(str(remote["url"]))
    return urls


def _url_matches_namespace(url: str, domain: str) -> bool:
    """True iff a source URL is consistent with the claimed namespace domain:
    its host is the domain (or a sub/super-domain of it), or it is a forge repo
    whose owner equals the domain's registrable label."""
    try:
        parts = urlsplit(url if "://" in url else f"https://{url}")
    except ValueError:
        return False
    host = (parts.hostname or "").lower().removeprefix("www.")
    if not host:
        return False
    if host == domain or host.endswith("." + domain) or domain.endswith("." + host):
        return True
    if host in _FORGE_REPO_HOSTS:
        owner = next((seg for seg in parts.path.split("/") if seg), "").lower()
        labels = domain.split(".")
        if owner and len(labels) >= 2 and owner == labels[-2]:
            return True
    return False


def _looks_like_registry_manifest(data) -> bool:
    """A server.json is an MCP registry manifest if its `$schema` names the MCP
    registry, or it has a name plus at least one package/remote. Fails closed so
    an unrelated file called server.json is never mistaken for one."""
    if not isinstance(data, dict):
        return False
    if _REGISTRY_SCHEMA_HINT in str(data.get("$schema", "")):
        return True
    return bool(data.get("name")) and bool(data.get("packages") or data.get("remotes"))


def registry_component_from_manifest(data, source: str) -> Component | None:
    if not _looks_like_registry_manifest(data):
        return None
    name = str(data.get("name") or "server")
    vars_ = _registry_vars(data)
    # A literal credential baked into the published manifest (a var/header that
    # is secret-shaped AND carries a value): it ships to everyone who installs.
    hardcoded = sorted({
        v["name"] for v in vars_
        if v["has_value"] and (v["is_secret"] or _is_secret_named(v["name"]))
    })
    # A secret-named variable the manifest never marks `isSecret`: clients and
    # logs will not redact it, and the registry cannot warn on it.
    unmarked = sorted({
        v["name"] for v in vars_
        if not v["has_value"] and not v["is_secret"] and _is_secret_named(v["name"])
    })
    deprecated = sorted({t for t in _registry_transports(data) if t in _DEPRECATED_TRANSPORTS})
    # A published package pinned to a mutable version (`latest`, or no version
    # at all): whoever installs from this manifest gets whatever the registry
    # serves that day, not the reviewed artifact - a supply-chain rug-pull
    # surface, the registry analogue of ATL-106.
    mutable = sorted({
        str(p.get("identifier") or p.get("name") or "package")
        for p in (data.get("packages") or [])
        if isinstance(p, dict)
        and str(p.get("version", "")).strip().lower() in ("", "latest")
    }) if isinstance(data.get("packages"), list) else []
    # Namespace-vs-source mismatch: derived only when the name claims a DNS
    # domain AND the manifest declares at least one comparable source URL.
    ns_domain = _namespace_domain(name)
    source_urls = _manifest_source_urls(data)
    ns_mismatch = bool(
        ns_domain and source_urls
        and not any(_url_matches_namespace(u, ns_domain) for u in source_urls)
    )
    attrs: dict = {
        "_registry_name": name,
        "_namespace_domain": ns_domain,
        "_namespace_mismatch": ns_mismatch,
        "_hardcoded_secret_vars": hardcoded,
        "_has_hardcoded_secret": bool(hardcoded),
        "_unmarked_secret_vars": unmarked,
        "_has_unmarked_secret": bool(unmarked),
        "_deprecated_transports": deprecated,
        "_mutable_pin_packages": mutable,
        "_has_mutable_pin": bool(mutable),
    }
    if data.get("description"):
        attrs["description"] = str(data["description"])
    return Component(
        id=f"mcp_registry_manifest.{name}",
        type="mcp_registry_manifest",
        name=name,
        source=source,
        attributes=attrs,
        trust_boundary="agent_runtime",
    )


def ingest_registry(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    if p.is_file():
        files = [p] if p.name == "server.json" else []
    else:
        files = sorted(p.rglob("server.json"))
    for f in files:
        try:
            data = _jsonc.loads(f.read_text(errors="ignore"))
        except json.JSONDecodeError:
            continue
        comp = registry_component_from_manifest(data, str(f))
        if comp is not None:
            model.add(comp)
    return model
