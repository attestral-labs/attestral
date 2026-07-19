"""Blast-radius scoring: rank every agent surface by its if-compromised reach.

The rules and the attack-path walk answer *is there* a bad path. They do not
answer *how bad is each component* - which tool server, if an injection landed
in it, would reach the most sensitive capability. This module does: for every
tool-granting surface it computes the weighted set of sensitive capabilities and
the cloud crossing reachable from that surface over the modeled design, and
ranks the surfaces by it. The lethal-trifecta host and the server that carries
cloud credentials rise to the top on their own, so hardening prioritises itself.

The reach graph, and its one honest assumption. Nodes are the model's
components; a surface reaches a sink either directly (it declares the capability,
or it holds cloud credentials) or through the shared agent runtime - once any one
co-resident tool is compromised, the agent can be induced to call any of its
siblings, so co-resident tool surfaces are mutually reachable. That is the same
action-space premise the lethal-trifecta detection already makes; it is stated
here, not hidden. Explicit model edges (cross-repo fleet links, the agent->cloud
crossing) extend the reach beyond the local runtime.

Weighting. Each sink class carries a sensitivity weight (code execution and a
cloud crossing weigh most; persistent memory least), and a reached sink is
discounted by distance - a capability a surface holds *directly* counts for more
than one it can only reach by pivoting through a sibling. The score is the summed
weight of the distinct sink classes a surface reaches, capped at 10 so it reads
on the same 0-10 axis as AARS.

Honest scope, inherited from every rule here: reachability is over DECLARED
capability in the modeled design - a sound over-approximation and a
prioritisation signal, never a proof that an injection would in fact succeed.
Deterministic, zero-dependency, runs on any model.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from attestral.model import SystemModel

# Sensitivity weight per sink class. Code execution (the pivot) and a cloud
# crossing (credentials that reach infrastructure) dominate; an outbound channel
# and sensitive-data access sit in the middle; persistent memory is the floor.
# The seven capability classes are model.CAPABILITY_CLASSES; "cloud" is the
# provable agent->cloud crossing (a server holding cloud credentials).
_SINK_WEIGHT = {
    "shell": 3.5,
    "cloud": 3.5,
    "database": 2.0,
    "saas_data": 2.0,
    "filesystem": 1.5,
    "network": 1.0,
    "messaging": 1.0,
    "memory": 0.5,
}

# Per-hop discount: a sink a surface holds directly (hop 0) counts fully; one it
# can only reach by inducing a sibling (hop 1+) is less certain, so it decays.
_DECAY = 0.5

# At or above this score, a component's blast radius is itself an agentic
# amplification factor - surfaced to AIVSS via the `_blast_radius` attribute.
FACTOR_THRESHOLD = 7.0


@dataclass
class BlastRadius:
    """One surface's if-compromised reach: the score and the sink classes it
    reaches, each with the nearest hop distance that reaches it."""
    component_id: str
    name: str
    type: str
    score: float
    reached: dict[str, int] = field(default_factory=dict)  # sink class -> nearest hop


def _sinks_of(component) -> dict[str, float]:
    """The sink classes this component IS - the sensitive things an attacker
    gains by landing here. Read from declared capabilities plus the cloud
    crossing a credential-holding server provides."""
    out: dict[str, float] = {}
    for cap in component.attr("_capabilities") or []:
        if cap in _SINK_WEIGHT:
            out[cap] = _SINK_WEIGHT[cap]
    if component.type == "mcp_server" and component.attr("_has_cloud_credentials"):
        out["cloud"] = _SINK_WEIGHT["cloud"]
    return out


def _adjacency(model: SystemModel) -> dict[str, set[str]]:
    """Directed cost-1 reach between components. Co-resident tool surfaces are
    mutually reachable (the shared runtime can be induced to call any of them);
    explicit model edges between real components add cross-runtime reach."""
    adj: dict[str, set[str]] = {}
    by_boundary: dict[str | None, list] = {}
    for c in model.tool_surfaces():
        by_boundary.setdefault(c.trust_boundary, []).append(c)
    for group in by_boundary.values():
        for a in group:
            for b in group:
                if a.id != b.id:
                    adj.setdefault(a.id, set()).add(b.id)
    for e in model.edges:
        s, t = model.get(e.source_id), model.get(e.target_id)
        if s and t and s.id != t.id:
            adj.setdefault(s.id, set()).add(t.id)
    return adj


def _distances(adj: dict[str, set[str]], start: str) -> dict[str, int]:
    """Breadth-first hop distance from `start` to every reachable component."""
    dist = {start: 0}
    level = [start]
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
    return dist


def blast_radius(model: SystemModel) -> list[BlastRadius]:
    """Score every tool-granting surface by its if-compromised reach, ranked
    worst first. Only surfaces that can carry an injection are scored - a passive
    cloud resource is a sink, not an actor, so it never appears here."""
    adj = _adjacency(model)
    sinks = {c.id: _sinks_of(c) for c in model.components}
    rows: list[BlastRadius] = []
    for s in model.tool_surfaces():
        dist = _distances(adj, s.id)
        nearest: dict[str, int] = {}
        for nid, d in dist.items():
            for cls in sinks.get(nid, {}):
                if cls not in nearest or d < nearest[cls]:
                    nearest[cls] = d
        score = sum(_SINK_WEIGHT[cls] * (_DECAY ** hop) for cls, hop in nearest.items())
        ordered = dict(sorted(nearest.items(), key=lambda kv: (kv[1], -_SINK_WEIGHT[kv[0]])))
        rows.append(BlastRadius(s.id, s.name, s.type, round(min(10.0, score), 1), ordered))
    rows.sort(key=lambda b: (-b.score, b.name))
    return rows


def annotate_blast_radius(model: SystemModel) -> list[str]:
    """Attach each surface's blast-radius score to its component (`_blast_radius`,
    read by AIVSS) and return notes for the caller to echo. Mutates in place;
    idempotent."""
    rows = blast_radius(model)
    for b in rows:
        c = model.get(b.component_id)
        if c is not None:
            c.attributes["_blast_radius"] = b.score
            c.attributes["_blast_radius_reached"] = b.reached
    if not rows or rows[0].score <= 0:
        return []
    top = rows[0]
    hot = sum(1 for b in rows if b.score >= FACTOR_THRESHOLD)
    note = f"blast radius: worst if-compromised reach is {top.name} at {top.score:.1f}/10"
    if hot:
        note += f"; {hot} surface(s) at or above {FACTOR_THRESHOLD:.0f}"
    return [note]


def _reached_label(cls: str, hop: int) -> str:
    return f"{cls} (self)" if hop == 0 else f"{cls} ({hop}h)"


def render_blast_radius(model: SystemModel, *, color: bool | None = None,
                        limit: int = 15) -> str:
    """A ranked blast-radius block for the terminal. Empty when the design has no
    tool-granting surface (nothing that can carry an injection)."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color
    if color is None:
        color = supports_color()
    rows = [b for b in blast_radius(model) if b.score > 0]
    if not rows:
        return ""
    lines = [_paint(
        f"Blast radius - if-compromised reach ({min(limit, len(rows))} of {len(rows)} surfaces)",
        "1;31", color)]
    for b in rows[:limit]:
        band = "1;31" if b.score >= 9 else "31" if b.score >= 7 else "33" if b.score >= 4 else "90"
        badge = _paint(f"{b.score:>4.1f}", band, color)
        reaches = ", ".join(_reached_label(cls, hop) for cls, hop in b.reached.items())
        lines.append(f"  {badge}  {_bold(b.name, color)} {_dim('(' + b.type + ')', color)}")
        lines.append(f"        {_dim('reaches:', color)} {reaches}")
    if len(rows) > limit:
        lines.append(_dim(f"  ... and {len(rows) - limit} more", color))
    lines.append(_dim(
        "  reach over declared capability in the modeled design - a prioritisation "
        "signal, not proof of exploitability.", color))
    return "\n".join(lines)
