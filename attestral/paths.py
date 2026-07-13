"""Attack-path synthesis: connect components into complete, named kill chains.

The deterministic rules each flag a *2-way* combination: a public endpoint and a
sensitive tool, a shell tool and an egress tool, untrusted input and a sink.
This module assembles them into an end-to-end path a human would otherwise have
to connect by hand: a way IN, a way to RUN CODE, and a way to GET DATA OUT, all
reachable in one agent session. That connected chain is the strongest thing a
whole-system model can express, and no per-component scanner can trace it.

Two entry types:

* external: an externally-reachable A2A endpoint. This chain has no single
  finding representing it, so it is also reported as ATL-210.
* internal: a tool that ingests attacker-influenceable content (a web fetcher,
  a SaaS reader, a memory store). This chain is already gated by findings
  (ATL-207 untrusted-input-to-sink, ATL-203 shell-plus-network), so it is not a
  separate finding; the value here is the assembled, named path.

The synthesizer is pure and deterministic. The engine and the terminal report
call it; keeping the traversal here keeps them thin.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from attestral.model import SystemModel

# Capability roles in a kill chain.
_ENTRY_TAINT_CAPS = {"network", "saas_data", "memory"}  # attacker-influenceable input
_PIVOT_CAPS = {"shell"}                                  # code / command execution
_EGRESS_CAPS = {"network", "messaging"}                  # a channel to move data out


@dataclass
class Stage:
    """One rung of an attack path: a role, a human label, the components that
    provide it."""
    role: str                    # "entry" | "pivot" | "impact"
    label: str
    components: list[str] = field(default_factory=list)


@dataclass
class AttackPath:
    kind: str                    # "external" | "internal"
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


def _pivot_and_impact(model: SystemModel) -> tuple[list[str], list[str], str]:
    """The shared back half of any chain: who can run code (pivot) and who
    provides a way out (egress capability or a cloud credential)."""
    comps = _capability_components(model)
    pivots = sorted({name for name, caps in comps if caps & _PIVOT_CAPS})
    egress = sorted({name for name, caps in comps if caps & _EGRESS_CAPS})
    cloud = sorted(
        c.name for c in model.by_type("mcp_server") if c.attr("_has_cloud_credentials")
    )
    impact_components = sorted(set(egress) | set(cloud))
    impact_label = " / ".join(
        (["exfiltration"] if egress else []) + (["cloud pivot"] if cloud else [])
    )
    return pivots, impact_components, impact_label


def external_attack_paths(model: SystemModel) -> list[AttackPath]:
    """Complete external kill chains: an externally-reachable A2A endpoint
    (entry), a code-execution tool (pivot), and an exfiltration or cloud sink
    (impact), all in one runtime. Returns [] unless all three stages exist.
    """
    public = sorted(
        c.name for c in model.by_type("a2a_agent") if c.attr("_effectively_public")
    )
    if not public:
        return []
    pivots, impact_components, impact_label = _pivot_and_impact(model)
    if not pivots or not impact_components:
        return []
    return [
        AttackPath(
            "external",
            Stage("entry", "external agent via public A2A endpoint", public),
            Stage("pivot", "code execution", pivots),
            Stage("impact", impact_label, impact_components),
        )
    ]


def internal_attack_paths(model: SystemModel) -> list[AttackPath]:
    """Complete internal kill chains: a tool that ingests attacker-influenceable
    content (entry), a code-execution tool (pivot), and an exfiltration or cloud
    sink (impact). Returns [] unless all three stages exist.

    Distinct from the external chain in its entry: the trigger is a prompt
    injection carried in content the agent reads, not an outside caller.
    """
    comps = _capability_components(model)
    sources = sorted({name for name, caps in comps if caps & _ENTRY_TAINT_CAPS})
    if not sources:
        return []
    pivots, impact_components, impact_label = _pivot_and_impact(model)
    if not pivots or not impact_components:
        return []
    return [
        AttackPath(
            "internal",
            Stage("entry", "untrusted input ingested by a tool", sources),
            Stage("pivot", "code execution", pivots),
            Stage("impact", impact_label, impact_components),
        )
    ]


def all_attack_paths(model: SystemModel) -> list[AttackPath]:
    """Every complete chain, external first. Used by the terminal report so the
    reviewer sees the assembled paths above the individual findings."""
    return external_attack_paths(model) + internal_attack_paths(model)
