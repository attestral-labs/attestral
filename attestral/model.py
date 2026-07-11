"""Unified system model: components, edges, trust boundaries, findings."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


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
    origin: str = "deterministic"   # deterministic | llm
    waived: bool = False            # suppressed by a documented waiver
    waiver_reason: str = ""         # justification, carried into the evidence chain
    judge_verdict: str = ""         # "" | confirmed | false_positive | needs_review
    judge_confidence: float = 0.0   # 0.0-1.0, set by the LLM-as-judge layer

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
