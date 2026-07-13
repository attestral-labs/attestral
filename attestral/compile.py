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
