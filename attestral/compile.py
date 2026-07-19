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

    servers: dict[str, dict] = {}
    for c in model.by_type("mcp_server"):
        entry: dict = {"allow": True, "constraints": {}, "attested_source": c.source}
        caps = c.attr("_capabilities") or []
        if caps:
            # The attested ambient capability envelope, so a re-attestation can be
            # checked as a narrowing (attestral compile --against): a server that
            # later gains a capability is an expansion that must be re-reviewed.
            entry["capabilities"] = sorted(caps)
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


TARGETS: dict[str, tuple] = {
    # target name -> (renderer over the neutral policy dict, default filename).
    # One source of truth so the CLI stays a pure dispatch. mcp-guard is the
    # default target; adding a target here is all it takes to wire it in.
    "mcp-guard": (render_policy_yaml, "mcp-guard-policy.yaml"),
    "cedar": (render_cedar, "attested-policy.cedar"),
}
