"""Cross-boundary reach: name the cloud resources an injectable agent surface can
actually reach.

Every per-server scanner stops at one fact: "this MCP server holds a cloud
credential." Attestral ingests the Terraform/K8s resources into the SAME system
model, joined to the agent by `credential_reach` and `references` edges, so it can
answer the question that actually decides the blast radius: from an injectable
surface that holds NO credential of its own, WHICH NAMED cloud resource is
reachable, and through which co-resident deputy.

A prompt injection in a benign web-fetch tool, laundered through a co-resident
cloud-deploy server's standing credential, reaching `aws_s3_bucket.customer_data`
- that agent->cloud confused-deputy path to a NAMED IaC sink is a graph property
no per-server scanner can express, because it needs the whole system model. It is
distinct from ATL-115 (a single server that is itself a confused deputy) and from
ATL-112 (a server that holds a cloud credential): this fires only when the
injectable entry and the credentialed deputy are DIFFERENT components, and it
names the concrete cloud resource at the end of the path.

Deterministic, zero-dependency. Reachability is over the modeled edges plus
declared capability: a sound over-approximation and a prioritisation signal, never
a proof that an injection would in fact succeed.
"""
from __future__ import annotations

from dataclasses import dataclass

from attestral.model import SystemModel

# Capabilities that make a surface an injection ENTRY: it ingests content an
# attacker can influence (a fetched page, a SaaS record, a memory the agent
# reads). Mirrors paths._ENTRY_TAINT_CAPS.
_TAINT_CAPS = {"network", "saas_data", "memory"}

# The boundaries a named infrastructure sink lives in.
_SINK_BOUNDARIES = {"cloud", "cluster"}

# Edges that carry reach ACROSS the agent->cloud boundary or WITHIN the cloud/
# cluster graph. Co-residence (same agent_runtime) is added separately.
_CROSS_EDGES = {"credential_reach", "references", "routes_to", "uses_service_account"}


@dataclass
class CrossBoundaryReach:
    """One confused-deputy path: an injectable entry, the co-resident credentialed
    deputy the injection is laundered through, and the named cloud/cluster
    resources reachable at the end of it."""
    entry: str                # injectable surface name (holds no credential itself)
    entry_id: str             # the entry component id, so a finding can attach to it
    deputy: str               # co-resident credential holder the injection pivots through
    sinks: list[str]          # named cloud/cluster resources reached ("type.name")
    example_path: list[str]   # a shortest path entry -> deputy -> nearest sink


def _is_named_sink(component) -> bool:
    return (
        component.trust_boundary in _SINK_BOUNDARIES
        and not component.type.startswith("boundary:")
        and not component.id.startswith("boundary:")
    )


def _reach_from(model: SystemModel, holder_id: str) -> dict[str, int]:
    """BFS over the credential/reference edge graph from a credential holder to
    every named cloud/cluster resource, returning resource id -> hop distance.
    Only `_CROSS_EDGES` are traversed, so this is the concrete infrastructure a
    standing credential's reach touches, including transitive escalation (a bucket
    the credential reaches, then the IAM role that governs it)."""
    adj: dict[str, set[str]] = {}
    for e in model.edges:
        if getattr(e, "kind", "") in _CROSS_EDGES:
            adj.setdefault(e.source_id, set()).add(e.target_id)
    dist = {holder_id: 0}
    level = [holder_id]
    depth = 0
    while level:
        depth += 1
        nxt = []
        for nid in level:
            for m in adj.get(nid, ()):
                if m not in dist:
                    dist[m] = depth
                    nxt.append(m)
        level = nxt
    return {rid: d for rid, d in dist.items()
            if d > 0 and _is_named_sink_id(model, rid)}


def _is_named_sink_id(model: SystemModel, cid: str) -> bool:
    c = model.get(cid)
    return c is not None and _is_named_sink(c)


def cross_boundary_reaches(model: SystemModel) -> list[CrossBoundaryReach]:
    """Every confused-deputy path from an injectable agent surface, through a
    DIFFERENT co-resident credential holder, into named cloud/cluster resources.
    Ordered by entry then deputy for determinism."""
    runtime = [c for c in model.tool_surfaces() if c.trust_boundary == "agent_runtime"]
    # Deputies: co-resident cloud-credential holders and the named infra each one
    # reaches. A holder that reaches nothing named is not a deputy worth naming.
    deputies: list[tuple[object, dict[str, int]]] = []
    for h in runtime:
        if not h.attr("_has_cloud_credentials"):
            continue
        reach = _reach_from(model, h.id)
        if reach:
            deputies.append((h, reach))
    if not deputies:
        return []
    # Entries: injectable surfaces that hold NO credential of their own, so the
    # only way they touch cloud is by inducing a co-resident deputy.
    entries = [
        c for c in runtime
        if not c.attr("_has_cloud_credentials")
        and set(c.attr("_capabilities") or []) & _TAINT_CAPS
    ]
    out: list[CrossBoundaryReach] = []
    for e in entries:
        for h, reach in deputies:
            if h.id == e.id:
                continue
            nearest_id = min(reach, key=lambda rid: (reach[rid], rid))
            sink_name = _label(model, nearest_id)
            out.append(CrossBoundaryReach(
                entry=e.name,
                entry_id=e.id,
                deputy=h.name,
                sinks=sorted(_label(model, rid) for rid in reach),
                example_path=[e.name, h.name, sink_name],
            ))
    out.sort(key=lambda r: (r.entry, r.deputy))
    return out


def _label(model: SystemModel, cid: str) -> str:
    c = model.get(cid)
    return f"{c.type}.{c.name}" if c else cid


def entry_detail(reaches: list[CrossBoundaryReach]) -> str:
    """The finding detail for ONE injectable entry: every deputy it can pivot
    through and the union of named cloud/cluster resources that path reaches."""
    entry = reaches[0].entry
    deputies = sorted({r.deputy for r in reaches})
    sinks = sorted({s for r in reaches for s in r.sinks})
    shown = sinks[:6]
    more = f" (+{len(sinks) - len(shown)} more)" if len(sinks) > len(shown) else ""
    path = " -> ".join(reaches[0].example_path)
    return (
        f"An injection in '{entry}' (which holds no credential of its own) can be "
        f"laundered through {len(deputies)} co-resident credential holder(s) "
        f"({', '.join(deputies)}) to reach {len(sinks)} named cloud/cluster "
        f"resource(s): {', '.join(shown)}{more}. Example path: {path}."
    )


# --- the full per-surface reach view (attestral reach) ------------------------
# ATL-222 fires the finding; this answers the demo question in front of it: for
# EVERY agent surface, which named cloud/Kubernetes resources can it touch, and
# how - directly (it holds the credential) or laundered through a co-resident
# deputy. The named resource at the end is the moat: it lives in the cloud model,
# not in any MCP server, so no per-server scanner can name it.

@dataclass
class ReachedSink:
    resource: str        # "type.name" of the cloud/cluster resource
    hops: int            # shortest hop distance from the surface
    via: str             # "direct" | "via <deputy>"


@dataclass
class SurfaceReach:
    surface: str
    surface_id: str
    injectable: bool       # ingests attacker-influenceable input
    holds_credential: bool
    sinks: list[ReachedSink]


def surface_reaches(model: SystemModel) -> list[SurfaceReach]:
    """For every agent-runtime tool surface, the named cloud/cluster resources it
    can reach and how. A surface reaches infrastructure directly when it holds the
    credential, or laundered when it is co-resident with a deputy that does. Sorted
    worst-first: injectable surfaces with the widest reach at the top, so the demo
    leads with the sentence that matters ('this benign tool reaches your bucket')."""
    runtime = [c for c in model.tool_surfaces() if c.trust_boundary == "agent_runtime"]
    holders = {h.id: _reach_from(model, h.id) for h in runtime
               if h.attr("_has_cloud_credentials")}
    holders = {hid: r for hid, r in holders.items() if r}
    out: list[SurfaceReach] = []
    for s in runtime:
        injectable = bool(set(s.attr("_capabilities") or []) & _TAINT_CAPS)
        holds = bool(s.attr("_has_cloud_credentials"))
        nearest: dict[str, ReachedSink] = {}
        # Direct: this surface's own credential reach.
        if s.id in holders:
            for rid, hop in holders[s.id].items():
                label = _label(model, rid)
                nearest[rid] = ReachedSink(label, hop, "direct")
        # Laundered: any co-resident deputy's reach, one hop further out.
        for hid, reach in holders.items():
            if hid == s.id:
                continue
            deputy = model.get(hid)
            for rid, hop in reach.items():
                cand = ReachedSink(_label(model, rid), hop + 1,
                                   f"via {deputy.name}" if deputy else "via deputy")
                if rid not in nearest or cand.hops < nearest[rid].hops:
                    nearest[rid] = cand
        if not nearest:
            continue
        sinks = sorted(nearest.values(), key=lambda k: (k.hops, k.resource))
        out.append(SurfaceReach(s.name, s.id, injectable, holds, sinks))
    # Worst first: injectable before credentialed-only, then by reach breadth.
    out.sort(key=lambda r: (not r.injectable, -len(r.sinks), r.surface))
    return out


def render_reach(model: SystemModel, *, color: bool | None = None) -> str:
    """Terminal-first cross-boundary reach report. Empty-safe: says so plainly when
    no agent surface can reach a modeled cloud/cluster resource."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    rows = surface_reaches(model)
    if not rows:
        return _paint("Cross-boundary reach: no agent surface reaches a modeled "
                      "cloud or Kubernetes resource in this design.", "32", color)
    lines = [_paint(
        f"Cross-boundary reach - what each agent surface can touch in your "
        f"infrastructure ({len(rows)} surface(s))", "1;31", color)]
    for r in rows:
        tags = []
        if r.injectable:
            tags.append(_paint("injectable", "1;31", color))
        if r.holds_credential:
            tags.append(_paint("holds credential", "33", color))
        tag = f"  [{', '.join(tags)}]" if tags else ""
        lines.append("")
        lines.append(f"  {_bold(r.surface, color)}{tag} "
                     f"{_dim('reaches ' + str(len(r.sinks)) + ' named resource(s):', color)}")
        for sk in r.sinks[:12]:
            hop = "self" if sk.hops == 0 else f"{sk.hops}h"
            lines.append(f"      {_bold(sk.resource, color)}  "
                         f"{_dim('(' + hop + ', ' + sk.via + ')', color)}")
        if len(r.sinks) > 12:
            lines.append(_dim(f"      ... and {len(r.sinks) - 12} more", color))
    lines.append("")
    lines.append(_dim(
        "An injectable surface that reaches named infrastructure is a cloud breach "
        "one prompt injection away (ATL-222). Reach is over the modeled edges - a "
        "prioritisation signal, not proof an injection would succeed.", color))
    return "\n".join(lines)


def reach_report(model: SystemModel) -> dict:
    """Machine-readable reach, for `attestral reach -o`."""
    return {
        "surfaces": [
            {
                "surface": r.surface, "injectable": r.injectable,
                "holds_credential": r.holds_credential,
                "reaches": [
                    {"resource": s.resource, "hops": s.hops, "via": s.via}
                    for s in r.sinks
                ],
            }
            for r in surface_reaches(model)
        ]
    }
