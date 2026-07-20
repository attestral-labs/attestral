"""Trust-asymmetry escalation for tool shadowing.

A tool-name collision between two equally-trusted first-party servers is most
likely a config mistake. The same collision between a trusted server and a
lower-trust one - an unpinned `@latest` package (a rug-pull surface), a remote
unauthenticated endpoint, a known-CVE package - is the shadowing attack itself:
the lower-trust server can answer calls the agent believes go to the trusted
tool.

This pass raises a collision finding (ATL-204 exact clash, ATL-219 confusable
clash) one severity band when the colliding servers span a trust asymmetry, and
names which side is the lower-trust shadower - exactly as reachability.py
escalates a finding that sits on a walked attack chain. ATL-205 is already
critical and ATL-206 is a within-identity conflict, so neither is in scope here.

Trust posture is read from what the ingester already derives about each server;
these are the same postures the pack flags on their own elsewhere (ATL-106
mutable pin, remote-unauthed, ATL-117 known CVE). Here they weight a collision
rather than standing alone. The signal is a prioritisation nudge, not a trust
verdict, and it only ever raises - a symmetric collision is left exactly as the
rule rated it.

Deterministic, zero-dependency. Idempotent: a finding this pass has already
escalated carries `escalated_from`, so a second pass is a no-op.
"""
from __future__ import annotations

from attestral.model import Finding, Severity, SystemModel
from attestral.rules.engine import _distinct_servers, _normalize_tool_name

_BANDS = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Collision rules whose finding component_id we can re-key to the servers behind
# it. The value builds the same key the matcher stamped on the finding.
_COLLISION_RULES = {"ATL-204", "ATL-219"}


# Mutable version tags: a launch that tracks one of these gets whatever the
# registry serves that day, not the reviewed artifact (ATL-106's rug-pull tag).
_MUTABLE_TAGS = ("@latest", ":latest")


def _has_mutable_tag(c) -> bool:
    joined = " ".join(str(a) for a in (c.attr("args") or []))
    return any(tag in joined for tag in _MUTABLE_TAGS)


def _lower_trust(c) -> bool:
    """A server is lower-trust when its launch identity is mutable or unverified:
    a mutable `@latest` / `:latest` tag (ATL-106), a remote unauthenticated
    endpoint, or a known-CVE package (ATL-117)."""
    return bool(_has_mutable_tag(c) or c.attr("_remote_unauthed")
                or c.attr("_has_known_cve"))


def _reason(c) -> str:
    if _has_mutable_tag(c):
        return "mutable @latest pin"
    if c.attr("_remote_unauthed"):
        return "remote, unauthenticated"
    if c.attr("_has_known_cve"):
        return "known-CVE package"
    return "lower trust"


def _collision_servers(model: SystemModel) -> dict[str, list]:
    """Re-derive the server set behind each collision finding, keyed exactly as
    the ATL-204 / ATL-219 matchers key the finding's component_id."""
    groups: dict[str, list] = {}
    for c in _distinct_servers(model):
        for t in dict.fromkeys(str(x) for x in (c.attr("_tool_names") or [])):
            groups.setdefault(f"model:tool:{t}", []).append(c)
            groups.setdefault(f"model:tool-confusable:{_normalize_tool_name(t)}", []).append(c)
    return groups


def annotate_trust_asymmetry(model: SystemModel, findings: list[Finding]) -> list[str]:
    """Raise a shadowing collision one severity band when the colliding servers
    span a trust asymmetry, naming the lower-trust shadower. Mutates in place and
    returns notes for the caller. Idempotent."""
    groups = _collision_servers(model)
    raised = 0
    for f in findings:
        if f.rule_id not in _COLLISION_RULES or f.escalated_from:
            continue
        servers = groups.get(f.component_id, [])
        lower = [c for c in servers if _lower_trust(c)]
        higher = [c for c in servers if not _lower_trust(c)]
        if not lower or not higher:
            continue  # symmetric: all equally trusted, or all lower-trust
        new_rank = min(f.severity.rank + 1, Severity.CRITICAL.rank)
        if new_rank <= f.severity.rank:
            continue
        f.escalated_from = f.severity.value
        f.severity = _BANDS[new_rank]
        named = ", ".join(f"{c.name} ({_reason(c)})"
                          for c in sorted(lower, key=lambda x: x.name))
        f.description += (
            f" Trust asymmetry: the colliding servers are not equally trusted - "
            f"lower-trust server(s) {named} can shadow a tool a more-trusted server owns.")
        raised += 1

    if not raised:
        return []
    return [f"trust-asymmetry: {raised} shadowing collision(s) raised one band "
            "(a lower-trust server can shadow a trusted tool)"]
