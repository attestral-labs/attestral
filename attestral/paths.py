"""Attack-path synthesis: connect components into complete, named kill chains.

The deterministic rules each flag a *2-way* combination - a public endpoint and
a sensitive tool, a shell tool and an egress tool. This module assembles them
into an end-to-end path a human would otherwise have to connect by hand:
a way IN, a way to RUN CODE, and a way to GET DATA OUT, all reachable in one
agent session. Producing that connected chain is the strongest expression of
what only a whole-system model can see - no per-component scanner can trace it.

The synthesizer is pure and deterministic (no eval, no I/O). ATL-210 reports
whatever it returns; keeping the traversal here keeps the engine a thin caller.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from attestral.model import SystemModel

# Capability roles in a kill chain.
_PIVOT_CAPS = {"shell"}                    # code / command execution
_EGRESS_CAPS = {"network", "messaging"}    # a channel to move data out


@dataclass
class Stage:
    """One rung of an attack path: a role, a human label, the components that
    provide it."""
    role: str                    # "entry" | "pivot" | "impact"
    label: str
    components: list[str] = field(default_factory=list)


@dataclass
class AttackPath:
    entry: Stage
    pivot: Stage
    impact: Stage

    def describe(self) -> str:
        return (
            f"{self.entry.label} [{', '.join(self.entry.components)}] "
            f"→ code execution [{', '.join(self.pivot.components)}] "
            f"→ {self.impact.label} [{', '.join(self.impact.components)}]"
        )


def _capability_components(model: SystemModel) -> list[tuple[str, set[str]]]:
    """(name, capabilities) for every component that hands the runtime tools:
    MCP servers and subagent delegates."""
    out: list[tuple[str, set[str]]] = []
    for c in list(model.by_type("mcp_server")) + list(model.by_type("subagent")):
        out.append((c.name, set(c.attr("_capabilities") or [])))
    return out


def external_attack_paths(model: SystemModel) -> list[AttackPath]:
    """Complete *external* kill chains: an externally-reachable A2A endpoint
    (entry), a code-execution tool (pivot), and an exfiltration or cloud sink
    (impact) - all present in one runtime. Returns [] unless all three stages
    exist, so an incomplete chain never produces a path.

    Deliberately keyed on an external A2A entry (not just any untrusted input):
    that is the distinct 'an outsider can drive the whole chain' finding, above
    the internal taint path (ATL-207) and the 2-way reachability rules.
    """
    public = sorted(
        c.name for c in model.by_type("a2a_agent") if c.attr("_effectively_public")
    )
    if not public:
        return []

    comps = _capability_components(model)
    pivots = sorted({name for name, caps in comps if caps & _PIVOT_CAPS})
    if not pivots:
        return []

    egress = sorted({name for name, caps in comps if caps & _EGRESS_CAPS})
    cloud = sorted(
        c.name for c in model.by_type("mcp_server") if c.attr("_has_cloud_credentials")
    )
    impact_components = sorted(set(egress) | set(cloud))
    if not impact_components:
        return []

    impact_label = " / ".join(
        (["exfiltration"] if egress else []) + (["cloud pivot"] if cloud else [])
    )
    return [
        AttackPath(
            entry=Stage("entry", "external agent via public A2A endpoint", public),
            pivot=Stage("pivot", "code execution", pivots),
            impact=Stage("impact", impact_label, impact_components),
        )
    ]
