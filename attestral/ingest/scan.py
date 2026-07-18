"""Directory scanner: routes files to the right ingesters and returns one model."""
from __future__ import annotations

from pathlib import Path

from attestral.ingest.agent_code import ingest_agent_code
from attestral.ingest.agent_config import ingest_agent_config
from attestral.ingest.dependencies import ingest_dependencies
from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.ingest.mcp import ingest_mcp, ingest_registry
from attestral.ingest.prompts import ingest_prompts
from attestral.ingest.terraform import ingest_terraform
from attestral.model import Edge, SystemModel, TrustBoundary


def build_model(path: str | Path) -> SystemModel:
    model = SystemModel(
        boundaries=[
            TrustBoundary("cloud", "Cloud infrastructure"),
            TrustBoundary("cluster", "Kubernetes cluster"),
            TrustBoundary("agent_runtime", "Agent / MCP runtime"),
        ]
    )
    ingest_terraform(path, model)
    ingest_kubernetes(path, model)
    ingest_mcp(path, model)
    ingest_registry(path, model)
    ingest_prompts(path, model)
    ingest_agent_config(path, model)
    ingest_agent_code(path, model)
    ingest_dependencies(path, model)
    _add_reachability_edges(model)
    _add_taint_edges(model)
    return model


# Capability classes that ingest attacker-influenceable content (taint sources)
# and that perform a sensitive action if driven by injected content (taint sinks).
_TAINT_SOURCE_CAPS = {"network", "saas_data", "memory"}
_TAINT_SINK_CAPS = {"shell"}


def _add_taint_edges(model: SystemModel) -> None:
    """Record unsafe-data-flow endpoints as edges (Kim et al. 2026 R3): a server
    that ingests untrusted input is a taint source, a server that can act on it
    is a sink. Landing them in the model JSON means the flow is part of the
    attested model hash - the structural signal ATL-207 reasons over. Spans
    every tool-granting surface, so a code-defined agent's taint endpoints are
    attested too."""
    for c in model.tool_surfaces():
        caps = set(c.attr("_capabilities") or [])
        if caps & _TAINT_SOURCE_CAPS:
            model.edges.append(Edge(
                source_id=c.id, target_id="taint:untrusted_input", kind="taint_source",
                attributes={"caps": sorted(caps & _TAINT_SOURCE_CAPS)},
            ))
        if caps & _TAINT_SINK_CAPS:
            model.edges.append(Edge(
                source_id=c.id, target_id="taint:sensitive_action", kind="taint_sink",
                attributes={"caps": sorted(caps & _TAINT_SINK_CAPS)},
            ))


def _add_reachability_edges(model: SystemModel) -> None:
    """Record provable agent->cloud crossings as edges, not just findings.

    A tool server holding cloud credentials is a live path from the
    agent_runtime boundary into the cloud boundary. The edge lands in the
    model JSON (and therefore in the model hash the policy pins), so the
    crossing is part of what gets attested.
    """
    for c in model.by_type("mcp_server"):
        if c.attr("_has_cloud_credentials"):
            model.edges.append(
                Edge(
                    source_id=c.id,
                    target_id="boundary:cloud",
                    kind="tool_access",
                    attributes={
                        "via": "cloud credentials in env",
                        "keys": c.attr("_cloud_credential_keys") or [],
                    },
                )
            )
