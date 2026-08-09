"""Compile an attested design into a runtime policy.

This is the loop-closer: the reviewed system model (plus its findings)
becomes an mcp-guard-compatible policy document. The threat model is not a
PDF - it is the runtime configuration.

Compilation rules (fail-closed):
- default: deny - servers absent from the attested model are never allowed
- critical findings against a server deny it outright (with the rule id as reason)
- filesystem scopes are narrowed to the attested roots; broad roots (ATL-102)
  compile to `allow: false` until re-scoped in the design
- non-TLS transports (ATL-101) compile to a tls_only constraint violation → deny
- env-secret findings (ATL-104) compile to a `forbid_env_secrets` constraint
- tool manifests are pinned: each server carries manifest_sha256 (canonical
  hash of launch identity + tool surface); drift re-hashes what actually runs
  and flags a mismatch as a rug-pull (DRF-005)
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re as _re

import yaml

from attestral.model import Finding, SystemModel

POLICY_VERSION = 1
_BROAD_ROOTS = {"/", "~", "/home", "/Users"}


def _model_hash(model: SystemModel) -> str:
    return hashlib.sha256(model.to_json().encode()).hexdigest()


def compile_policy(
    model: SystemModel,
    findings: list[Finding],
    chain_head: str = "",
) -> dict:
    """Return an mcp-guard v0 policy dict derived from the attested design."""
    by_component: dict[str, list[Finding]] = {}
    for f in findings:
        by_component.setdefault(f.component_id, []).append(f)

    # Servers the attested design routes through a credential broker: an
    # agentgateway route fronts them (matched by name). Recorded on each entry so
    # the drift layer can catch a runtime call that bypassed the broker (DRF-011,
    # CB4A TM-11) - the runtime complement to the static ATL-221.
    brokered_names = {c.name for c in model.by_type("agentgateway_route")}

    servers: dict[str, dict] = {}
    for c in model.by_type("mcp_server"):
        entry: dict = {"allow": True, "constraints": {}, "attested_source": c.source}
        if c.name in brokered_names:
            entry["broker_required"] = True
        # The attested ambient capability envelope, emitted for every mcp_server
        # (present even when empty). Two uses: a re-attestation is checked as a
        # narrowing (attestral compile --against) - a server that later gains a
        # capability is an expansion that must be re-reviewed; and drift compares
        # a runtime-observed capability against this set (DRF-008). Emitting it
        # unconditionally is load-bearing for DRF-008: a "key present, list empty"
        # envelope (a bare `uvx toolrunner` with no modeled capability) is a KNOWN
        # empty envelope that fires on any out-of-set capability, and is thereby
        # distinguishable from an absent key (a legacy/hand-written policy), which
        # is an UNKNOWN envelope drift must never fire on.
        entry["capabilities"] = sorted(c.attr("_capabilities") or [])
        if c.attr("_manifest_hash"):
            entry["manifest_sha256"] = c.attr("_manifest_hash")
        server_findings = by_component.get(c.id, [])
        deny_reasons = [
            f.rule_id for f in server_findings if f.severity.value == "critical"
        ]

        # Transport: attested design must be TLS; http:// compiles to deny.
        url = str(c.attr("url", ""))
        if url:
            entry["constraints"]["transport"] = "tls_only"
            if url.startswith("http://"):
                deny_reasons.append("ATL-101")

        # Filesystem scope: allow only attested, non-broad roots.
        args = [str(a) for a in (c.attr("args") or [])]
        roots = [a for a in args if a.startswith(("/", "~"))]
        if roots:
            narrow = [r for r in roots if r not in _BROAD_ROOTS]
            if narrow:
                entry["constraints"]["root_paths"] = sorted(narrow)
            else:
                deny_reasons.append("ATL-102")

        # Secrets in env: enforce at the proxy.
        if c.attr("_env_has_secrets"):
            entry["constraints"]["forbid_env_secrets"] = True

        if deny_reasons:
            entry["allow"] = False
            entry["reason"] = (
                "denied by attested design review: " + ", ".join(sorted(set(deny_reasons)))
            )
            entry.pop("constraints", None)

        servers[c.name] = entry

    return {
        "version": POLICY_VERSION,
        "metadata": {
            "generated_by": "attestral",
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "model_hash": _model_hash(model),
            "review_chain_head": chain_head,
        },
        "default": "deny",
        # Resource-drain / DoS budgets (Kim et al. 2026 R7). Tunable knobs the
        # drift layer enforces against runtime telemetry: a runaway loop (the
        # same call repeated past loop_repeat_threshold) is DRF-006; a server
        # invoked more than max_calls_per_server times in the window is DRF-007.
        # Defaults are generous; tighten per workload.
        "budgets": {
            "loop_repeat_threshold": 5,
            "max_calls_per_server": 100,
        },
        "servers": servers,
    }


def render_policy_yaml(policy: dict) -> str:
    header = (
        "# mcp-guard policy - COMPILED FROM AN ATTESTED DESIGN REVIEW.\n"
        "# Do not hand-edit: change the design, re-review, re-compile.\n"
        f"# model_hash: {policy['metadata']['model_hash'][:16]}…  "
        f"chain_head: {(policy['metadata']['review_chain_head'] or '-')[:16]}\n"
    )
    return header + yaml.safe_dump(policy, sort_keys=False)


def _cedar_str(s: str) -> str:
    """Escape a Python string for use inside a Cedar double-quoted literal.

    Cedar quoted strings (entity ids and annotation values) are hand-built here,
    so unlike ``yaml.safe_dump`` nothing escapes them for us. Backslash first,
    then the quote, then the control characters Cedar recognises. This is the
    string-safety invariant: a server name with a quote or backslash must never
    break out of its literal.
    """
    s = str(s)
    s = s.replace("\\", "\\\\")
    s = s.replace('"', '\\"')
    s = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
    return s


def _cedar_when(constraints: dict) -> str | None:
    """Render a server's constraints as a single Cedar ``when { ... }`` clause.

    Conditions AND together in a deterministic order (transport, root_paths,
    forbid_env_secrets). Returns None when there is nothing to constrain, so the
    permit is emitted with no ``when`` clause. A missing context attribute makes
    a permit's condition fail, which denies - fail-closed, matching Attestral.
    """
    conds: list[str] = []
    if constraints.get("transport") == "tls_only":
        conds.append('context.transport == "tls"')
    roots = constraints.get("root_paths")
    if roots:
        members = ", ".join(f'"{_cedar_str(r)}"' for r in roots)
        conds.append(f"[{members}].contains(context.root_path)")
    if constraints.get("forbid_env_secrets"):
        conds.append("context.env_has_secrets == false")
    if not conds:
        return None
    return "when { " + " && ".join(conds) + " };"


def _cedar_annotations(entry: dict) -> list[str]:
    """Machine-readable provenance annotations for a policy block.

    Keys must be valid snake_case Cedar identifiers and unique within a policy,
    so capabilities collapse into ONE comma-joined ``@capabilities`` annotation
    rather than repeating ``@capability`` (a duplicate key is a Cedar error).
    Fields that only exist on one base are read defensively with ``.get``.
    """
    ann: list[str] = []
    src = entry.get("attested_source")
    if src:
        ann.append(f'@attested_source("{_cedar_str(src)}")')
    manifest = entry.get("manifest_sha256")
    if manifest:
        ann.append(f'@manifest_sha256("{_cedar_str(manifest)}")')
    caps = entry.get("capabilities")
    if caps:
        joined = ",".join(_cedar_str(c) for c in caps)
        ann.append(f'@capabilities("{joined}")')
    return ann


def render_cedar(policy: dict) -> str:
    """Render the neutral policy dict as a Cedar authorization policy.

    Same intermediate representation as ``render_policy_yaml``; only the surface
    syntax differs. Cedar's native semantics carry the load: an implicit deny for
    any server without a ``permit``, and a ``forbid`` that overrides any permit.
    Pure string building, no new dependency. Full validation is external
    (the ``cedar`` CLI), which we deliberately do not vendor.
    """
    meta = policy["metadata"]
    budgets = policy.get("budgets", {})
    lines: list[str] = [
        "// Cedar authorization policy - COMPILED FROM AN ATTESTED DESIGN REVIEW.",
        "// Do not hand-edit: change the design, re-review, re-compile.",
        f"// model_hash: {meta['model_hash'][:16]}  "
        f"chain_head: {(meta.get('review_chain_head') or '-')[:16]}",
        f"// generated_at: {meta.get('generated_at', '-')}",
        "// Cedar default is implicit deny: any MCP server without a permit below is denied.",
        "// Budgets are documentation only in Cedar "
        f"(loop_repeat_threshold={budgets.get('loop_repeat_threshold', '-')}, "
        f"max_calls_per_server={budgets.get('max_calls_per_server', '-')}).",
        "// Cedar is a stateless per-request evaluator, so mcp-guard and attestral "
        "drift remain their enforcer.",
    ]

    blocks: list[str] = []
    for name, entry in sorted(policy["servers"].items()):
        principal = f'MCPServer::"{_cedar_str(name)}"'
        block: list[str] = []
        if entry["allow"]:
            block.extend(_cedar_annotations(entry))
            block.append("permit (")
            block.append(f"  principal == {principal},")
            block.append('  action == Action::"invoke",')
            when = _cedar_when(entry.get("constraints", {}) or {})
            block.append("  resource")
            if when:
                block.append(")")
                block.append(when)
            else:
                block.append(");")
        else:
            reason = str(entry.get("reason", "") or "")
            for rline in reason.split("\n"):
                block.append(f"// {rline}")
            block.extend(_cedar_annotations(entry))
            block.append("forbid (")
            block.append(f"  principal == {principal},")
            block.append("  action,")
            block.append("  resource")
            block.append(");")
        blocks.append("\n".join(block))

    return "\n".join(lines) + "\n\n" + "\n\n".join(blocks) + "\n"


def render_agentgateway(policy: dict) -> str:
    """Render the attested design as a default-deny agentgateway credential-broker
    config (CB4A Model A/B). Every attested-allowed server becomes one route with
    strict inbound authentication and a per-call token-exchange backend, so the
    agent never holds a standing credential; a server the review denied is simply
    not emitted, and agentgateway denies any route it does not know. This is the
    moat closed on the credential layer: the review is the broker policy, not a
    hand-written artifact that can drift from it. The operator supplies the token
    endpoint and OAuth client per route; the client secret is always a secretRef,
    never inlined (which ATL-167 would flag on the way back in)."""
    meta = policy["metadata"]
    routes: list[dict] = []
    for name, entry in sorted(policy["servers"].items()):
        if not entry.get("allow", False):
            continue  # denied by the attested review -> not routable (default-deny)
        routes.append({
            "name": name,
            # Default-deny at the front door: every caller is authenticated before
            # any credential is brokered. A route with anything weaker is ATL-166.
            "policies": {"jwtAuth": {"mode": "strict"}},
            "backends": [{
                "mcp": {"name": name},
                "backendAuth": {"oauthTokenExchange": {
                    # The broker mints a short-lived, scoped token per call via
                    # RFC 8693 token exchange; fill host/tokenEndpointPath for your
                    # IdP. The secret is referenced, never inlined.
                    "host": "REPLACE_WITH_IDP_HOST:443",
                    "tokenEndpointPath": "/oauth2/v1/token",
                    "clientAuth": {
                        "clientId": f"attestral-{name}",
                        "secretRef": {"name": f"{name}-oauth-client"},
                    },
                }},
            }],
        })
    config = {"binds": [{"port": 3000, "listeners": [{"routes": routes}]}]}
    header = (
        "# agentgateway credential-broker policy - COMPILED FROM AN ATTESTED DESIGN REVIEW.\n"
        "# Default-deny: only attested-allowed servers are routable, each behind strict\n"
        "# inbound auth and per-call token exchange, so no agent holds a standing key.\n"
        "# Do not hand-edit: change the design, re-review, re-compile.\n"
        f"# model_hash: {meta['model_hash'][:16]}…  "
        f"chain_head: {(meta['review_chain_head'] or '-')[:16]}\n"
    )
    return header + yaml.safe_dump(config, sort_keys=False)


def policy_digest(policy: dict, renderer) -> str:
    """SHA-256 of a policy rendering, with the non-deterministic timestamp neutralized.

    `compile_policy` stamps `metadata.generated_at` with the wall clock, and the
    Cedar renderer emits it into the policy text, so hashing the rendered bytes
    directly would produce a fresh digest on every run and a re-verification
    would falsely FAIL. Deep-copy the policy, blank `generated_at` only (the
    binding fields `model_hash` and `review_chain_head` stay, so a swapped design
    still changes the digest), render, and hash. The attest and verify paths both
    call this one helper, so they never diverge on how the policy is normalized.
    """
    import copy

    normalized = copy.deepcopy(policy)
    meta = normalized.get("metadata")
    if isinstance(meta, dict):
        meta["generated_at"] = ""
    return hashlib.sha256(renderer(normalized).encode()).hexdigest()


# The per-OS directories Claude Code reads its enterprise-managed config from.
# Surfaced in the compile output so an operator knows where to deploy the files
# via MDM/Jamf/Intune/GPO. Verified against code.claude.com/docs/en/managed-mcp
# (Aug 2026); the legacy Windows C:\ProgramData path was dropped at v2.1.75.
CLAUDE_MANAGED_PATHS = {
    "macOS": "/Library/Application Support/ClaudeCode/",
    "Linux": "/etc/claude-code/",
    "Windows": "C:\\Program Files\\ClaudeCode\\",
}


def _managed_launch(component) -> dict:
    """One attested-allowed server as a managed-mcp.json entry, from its launch
    identity. A remote server carries a `url` (rendered as an http server); a
    local one carries `command` + `args` (a stdio server). Same schema Claude
    Code reads for a project `.mcp.json`, so the emitted file is directly
    loadable."""
    url = str(component.attr("url") or "")
    if url:
        return {"type": "http", "url": url}
    entry: dict = {"type": "stdio", "command": str(component.attr("command") or "")}
    args = [str(a) for a in (component.attr("args") or [])]
    if args:
        entry["args"] = args
    return entry


def _managed_match(component) -> dict | None:
    """A `serverUrl` / `serverCommand` allow-or-deny match for one server, or None
    when the server carries neither. Deliberately NEVER keys on `serverName`: the
    managed-config docs state serverName-only matching is not a security control
    (a user can name any server `github`), so the allowlist must pin the launch
    identity. The caller falls back to a bare serverName ONLY on the deny side,
    where over-blocking is safe."""
    url = str(component.attr("url") or "")
    if url:
        return {"serverUrl": url}
    command = str(component.attr("command") or "")
    if command:
        args = [str(a) for a in (component.attr("args") or [])]
        return {"serverCommand": [command, *args]}
    return None


def compile_claude_managed(model: SystemModel, policy: dict) -> dict[str, str]:
    """The attested design as Claude Code enterprise-managed config: two files.

    `managed-mcp.json` is EXCLUSIVE control - Claude Code loads only the servers
    it names and refuses `claude mcp add` (and `--mcp-config`), so a server the
    review denied physically cannot run on a managed machine. It carries the
    attested-allowed servers only; the review's denials are simply absent, which
    is the strongest default-deny Claude Code offers.

    `managed-settings.json` layers the softer allowlist/denylist policy for the
    approved-catalog case, plus `disableSideloadFlags` (which closes the
    `--mcp-config` bypass of the allowlist path, issue #31508). Its allow and deny
    entries pin `serverUrl`/`serverCommand`, never the self-assigned `serverName`.

    Unlike the policy-only TARGETS renderers, this needs the MODEL for each
    server's launch identity (the compiled policy dict does not carry it), so the
    compile CLI special-cases it rather than routing through TARGETS.
    """
    comps = {c.name: c for c in model.by_type("mcp_server")}
    managed_servers: dict = {}
    allow_entries: list = []
    deny_entries: list = []
    for name, entry in sorted((policy.get("servers") or {}).items()):
        c = comps.get(name)
        if entry.get("allow"):
            if c is not None:
                managed_servers[name] = _managed_launch(c)
                match = _managed_match(c)
                if match is not None:
                    allow_entries.append(match)
        else:
            # Denied by the review: omit from managed-mcp.json (it cannot load)
            # AND denylist it (a denylist entry wins over any allow, so it stays
            # blocked even if a laxer settings layer would permit it).
            match = _managed_match(c) if c is not None else None
            deny_entries.append(match or {"serverName": name})
    managed_mcp = {"mcpServers": managed_servers}
    managed_settings = {
        "allowManagedMcpServersOnly": True,
        "allowedMcpServers": allow_entries,
        "deniedMcpServers": deny_entries,
        "disableSideloadFlags": True,
    }
    return {
        "managed-mcp.json": json.dumps(managed_mcp, indent=2) + "\n",
        "managed-settings.json": json.dumps(managed_settings, indent=2) + "\n",
    }


# The MCP server.json schema every registry catalog entry declares.
REGISTRY_SERVER_SCHEMA = (
    "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json"
)
# command -> the registry package ecosystem it launches from, for the stdio case.
_REGISTRY_TYPE = {"npx": "npm", "uvx": "pypi", "uv": "pypi", "pipx": "pypi"}


def _copilot_server_name(component) -> str:
    """A reverse-DNS server name for the registry catalog. A server ingested from
    a real server.json already carries one (a namespace with a dot, one `/`); any
    other name is synthesized under a local namespace so the entry is schema-valid.
    In Copilot's "Registry only" mode the catalog DEFINES the canonical server ids
    users install by, so a synthesized name is the enforced id, not a mismatch."""
    name = str(component.name)
    ns = name.split("/", 1)[0] if "/" in name else ""
    if "/" in name and "." in ns:
        return name
    slug = _re.sub(r"[^a-z0-9_.-]", "-", name.lower()).strip("-.") or "server"
    return f"com.attestral.local/{slug}"


def _copilot_package(component) -> dict | None:
    """A `packages[]` entry for a stdio server launched via npx/uvx, or None when
    the launch form has no resolvable registry package. The identifier and version
    are split from the first non-flag launch arg (`@scope/name@version` or
    `name@version`), so the catalog entry is installable rather than name-only."""
    command = str(component.attr("command") or "").lower().rsplit("/", 1)[-1]
    registry_type = _REGISTRY_TYPE.get(command)
    if not registry_type:
        return None
    for arg in [str(a) for a in (component.attr("args") or [])]:
        if arg.startswith("-"):
            continue  # a flag (-y, --key), not the package spec
        at = arg.rfind("@")
        identifier, version = (arg[:at], arg[at + 1:]) if at > 0 else (arg, "")
        pkg: dict = {"registryType": registry_type, "identifier": identifier,
                     "transport": {"type": "stdio"}}
        if version:
            pkg["version"] = version
        return pkg
    return None


def _copilot_entry(component) -> dict:
    """One attested-allowed server as a wrapped registry `ServerResponse`: the
    server.json under `server`, plus the registry-managed `_meta` block. Timestamps
    are deliberately omitted (optional per schema) so the catalog is deterministic;
    `status`/`isLatest` are emitted so the entry reads as canonical and the
    version-latest lookup is unambiguous."""
    description = str(component.attr("description") or f"MCP server {component.name}")
    server: dict = {
        "$schema": REGISTRY_SERVER_SCHEMA,
        "name": _copilot_server_name(component),
        "description": description[:100] or "MCP server",
        "version": str(component.attr("version") or "0.0.0"),
    }
    url = str(component.attr("url") or "")
    if url:
        server["remotes"] = [{"type": "streamable-http", "url": url}]
    else:
        pkg = _copilot_package(component)
        if pkg is not None:
            server["packages"] = [pkg]
    return {
        "server": server,
        "_meta": {"io.modelcontextprotocol.registry/official":
                  {"status": "active", "isLatest": True}},
    }


def compile_copilot_registry(model: SystemModel, policy: dict) -> str:
    """The attested-allowed servers as a GitHub Copilot internal MCP registry v0.1
    catalog - the `GET /v0.1/servers` list response body.

    An org points Copilot's "MCP Registry URL" at a host serving this, sets
    enforcement to "Registry only", and Copilot then lets developers install only
    the servers the review admitted. Denied servers are simply absent from the
    catalog. Enforcement is by server name (exact match), and in Registry-only
    mode the catalog defines those names, so the emitted ids are the enforced ids.

    Emits the list envelope only (the primary endpoint Copilot enumerates); the
    per-server `/versions/latest` route serves the same wrapped entry, and the
    compile output states the base-URL and CORS requirements the host must meet.
    """
    comps = {c.name: c for c in model.by_type("mcp_server")}
    entries: list[dict] = []
    for name, entry in sorted((policy.get("servers") or {}).items()):
        c = comps.get(name)
        if entry.get("allow") and c is not None:
            entries.append(_copilot_entry(c))
    catalog = {"servers": entries, "metadata": {"count": len(entries)}}
    return json.dumps(catalog, indent=2) + "\n"


TARGETS: dict[str, tuple] = {
    # target name -> (renderer over the neutral policy dict, default filename).
    # One source of truth so the CLI stays a pure dispatch. mcp-guard is the
    # default target; adding a POLICY-ONLY target here is all it takes to wire it
    # in. The `claude-managed` and `copilot-registry` targets are intentionally
    # NOT here: they need the model for each server's launch identity, so the CLI
    # special-cases them.
    "mcp-guard": (render_policy_yaml, "mcp-guard-policy.yaml"),
    "cedar": (render_cedar, "attested-policy.cedar"),
    "agentgateway": (render_agentgateway, "agentgateway-policy.yaml"),
}

# All compile targets the CLI accepts (the policy-only TARGETS plus the
# model-aware special cases).
COMPILE_TARGETS = [*TARGETS, "claude-managed", "copilot-registry"]
