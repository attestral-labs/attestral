"""Unified system model: components, edges, trust boundaries, findings."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


# Component types that hand the agent runtime capabilities (tools). The
# fleet-level rules, attack-path synthesis, red-team walk, and AIVSS all reason
# over this union so a capability combo composes across every tool-granting
# surface, wherever it was declared: an MCP server, a delegated subagent, or an
# agent defined directly in framework code.
TOOL_GRANTING_TYPES = ("mcp_server", "subagent", "code_agent")

# The coarse capability classes a tool-granting component can be tagged with in
# `_capabilities`. This is the single source of truth for the capability
# vocabulary: the mcp ingester emits exactly these tokens (a shell launch ->
# "shell", the substring hints -> the rest), and drift compares an observed
# runtime capability against a server's attested envelope over the same set.
# A child-process/exec spawn is "shell" (never "process"); a socket is "network".
# Kept in the model, not the ingester, so drift can share it without importing
# the heavy ingest module. A guard test asserts the ingester cannot emit a token
# outside this set, so the two never silently desync.
CAPABILITY_CLASSES = frozenset({
    "shell", "filesystem", "network", "messaging", "database", "saas_data", "memory",
})


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


# Confidence ordering for the false-positive budget (--min-confidence).
CONFIDENCE_RANK = {"high": 3, "medium": 2, "low": 1}


@dataclass
class Component:
    """A node in the system model: cloud resource, service, MCP server, agent, datastore."""
    id: str
    type: str                       # e.g. aws_s3_bucket, mcp_server, agent, service
    name: str
    source: str                     # file path the component was ingested from
    attributes: dict[str, Any] = field(default_factory=dict)
    trust_boundary: str | None = None

    def attr(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)


@dataclass
class Edge:
    """A directed relationship: data flow, invocation, tool access, network path."""
    source_id: str
    target_id: str
    kind: str = "dataflow"          # dataflow | invokes | tool_access | network
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class TrustBoundary:
    id: str
    name: str
    description: str = ""


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    component_id: str
    description: str
    recommendation: str
    source: str = ""
    framework_refs: list[str] = field(default_factory=list)   # e.g. ["ASVS V1.2", "NIST AC-3"]
    origin: str = "deterministic"   # deterministic | llm | ml
    confidence: str = "high"        # high | medium | low - how FP-prone this rule
                                    # is. Structural deterministic rules default
                                    # high (0 FP on the benign corpus); the ML
                                    # tier sets it from its score. --min-confidence
                                    # filters on it.
    reachability: str = ""          # walked attack chain this finding's component sits on
    reachability_role: str = ""     # the component's rung(s): entry | pivot | impact
    escalated_from: str = ""        # original severity band, when reachability raised it
    waived: bool = False            # suppressed by a documented waiver
    waiver_reason: str = ""         # justification, carried into the evidence chain
    waived_by: str = ""             # who accepted the risk (attestral accept provenance)
    waived_at: str = ""             # ISO date the risk was accepted
    judge_verdict: str = ""         # "" | confirmed | false_positive | needs_review
    judge_confidence: float = 0.0   # 0.0-1.0, set by the LLM-as-judge layer

    def meets_confidence(self, floor: str) -> bool:
        """True if this finding's confidence is at or above `floor`."""
        return CONFIDENCE_RANK.get(self.confidence, 3) >= CONFIDENCE_RANK.get(floor, 1)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class SystemModel:
    components: list[Component] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    boundaries: list[TrustBoundary] = field(default_factory=list)

    def add(self, component: Component) -> None:
        self.components.append(component)

    def by_type(self, prefix: str) -> list[Component]:
        return [c for c in self.components if c.type.startswith(prefix)]

    def tool_surfaces(self) -> list[Component]:
        """Every component that grants the agent runtime tools, across all
        tool-granting types (see TOOL_GRANTING_TYPES). This is the union the
        fleet rules, attack-path synthesis, and AIVSS reason over."""
        return [c for c in self.components if c.type in TOOL_GRANTING_TYPES]

    def get(self, component_id: str) -> Component | None:
        return next((c for c in self.components if c.id == component_id), None)

    def crossing_edges(self) -> list[Edge]:
        """Edges whose endpoints sit in different trust boundaries."""
        out = []
        for e in self.edges:
            s, t = self.get(e.source_id), self.get(e.target_id)
            if s and t and s.trust_boundary != t.trust_boundary:
                out.append(e)
        return out

    def to_json(self) -> str:
        return json.dumps(
            {
                "components": [asdict(c) for c in self.components],
                "edges": [asdict(e) for e in self.edges],
                "boundaries": [asdict(b) for b in self.boundaries],
            },
            indent=2,
            default=str,
        )
