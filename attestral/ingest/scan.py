"""Directory scanner: routes files to the right ingesters and returns one model."""
from __future__ import annotations

from pathlib import Path

from attestral.ingest.kubernetes import ingest_kubernetes
from attestral.ingest.mcp import ingest_mcp
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
    ingest_prompts(path, model)
    _add_reachability_edges(model)
    return model


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
