"""Directory scanner: routes files to the right ingesters and returns one model.

Besides the per-file ingesters, this module derives the model-level edges:
the taint endpoints and the agent->cloud boundary sentinel (both preserved
unchanged), and the component-to-component `credential_reach` family - a
surface holding a provider's cloud credentials reaches every SAME-provider
cloud component in the scan (AWS keys -> aws_*, GCP -> google_*, Azure ->
azurerm_*; never cross-provider). To keep a large estate from exploding the
edge list, per (holder, provider) the reach is capped at the first
_CREDENTIAL_REACH_CAP components in sorted-id order - a deterministic sample
for the mesh and hop analysis, while the `boundary:cloud` sentinel edge keeps
attesting the *full* crossing regardless of the cap.
"""
from __future__ import annotations

from pathlib import Path

from attestral.ingest.agent_code import ingest_agent_code
from attestral.ingest.agent_config import ingest_agent_config
from attestral.ingest.agentgateway import ingest_agentgateway
from attestral.ingest.dependencies import ingest_dependencies
from attestral.ingest.deployment_env import ingest_deployment_env
from attestral.ingest.github_actions import ingest_github_actions
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
    ingest_agentgateway(path, model)
    ingest_deployment_env(path, model)
    ingest_dependencies(path, model)
    ingest_github_actions(path, model)
    # The CI boundary is seeded only when a workflow was actually ingested:
    # the model hash covers the boundary list, so an unconditional fourth
    # boundary would silently change the attested hash of every workflow-free
    # design (breaking `--against` pins and the compile goldens) for nothing.
    if model.by_type("ci_workflow"):
        model.boundaries.append(TrustBoundary("ci", "CI/CD pipeline"))
    _add_reachability_edges(model)
    _add_taint_edges(model)
    _add_credential_reach_edges(model)
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


# Provider family -> the terraform component-type prefix of the SAME provider.
# Same-provider only, ever: an AWS key says nothing about a google_* resource.
_PROVIDER_PREFIX = {"aws": "aws_", "azure": "azurerm_", "gcp": "google_"}

# Env-key markers per provider family, read off the cloud-credential keys the
# ingesters derived. KUBECONFIG proves a cluster crossing, not a cloud
# provider, so it deliberately maps to no family here (fail closed).
_PROVIDER_KEY_MARKERS = (
    ("aws", ("AWS_",)),
    ("azure", ("AZURE_",)),
    ("gcp", ("GOOGLE_", "GCP_", "GCLOUD")),
)

# Per (holder, provider) cap on credential_reach edges - see module docstring.
_CREDENTIAL_REACH_CAP = 25


def _provider_families(keys: list) -> list[str]:
    """The cloud provider families a set of credential env keys spans."""
    families: set[str] = set()
    for raw in keys or []:
        k = str(raw).upper()
        for family, markers in _PROVIDER_KEY_MARKERS:
            if any(m in k for m in markers):
                families.add(family)
    return sorted(families)


def _add_credential_reach_edges(model: SystemModel) -> None:
    """Emit `credential_reach` edges: a credential-holding surface -> each
    same-provider cloud component in the scan.

    This is the agent-to-cloud moat made graph-visible: the `boundary:cloud`
    sentinel already attests THAT a crossing exists; these edges say WHICH
    modeled cloud components the credential actually reaches, so the
    blast-radius adjacency, the topography mesh, and the proof walker can put
    the agent and the cloud in one connected graph. Feeds the reachability
    risk chain (an injection landing on the holder operates on these
    resources). Inferred reach, so it carries its own kind - a consumer can
    always tell it apart from a declared `references`/`routes_to` edge.

    Holders: an mcp_server with `_has_cloud_credentials` (families read from
    `_cloud_credential_keys`) or a k8s_container whose `_credential_providers`
    include a cloud family. Same-provider only; no holder, no matching cloud
    component, or no family => no edge. Deterministic: holders in model order,
    families sorted, targets in sorted-id order, capped per the module
    docstring."""
    cloud_by_family: dict[str, list] = {}
    for c in model.components:
        if c.trust_boundary != "cloud":
            continue
        for family, prefix in _PROVIDER_PREFIX.items():
            if c.type.startswith(prefix):
                cloud_by_family.setdefault(family, []).append(c)
                break
    if not cloud_by_family:
        return
    for targets in cloud_by_family.values():
        targets.sort(key=lambda c: c.id)
    for holder in model.components:
        if holder.type == "mcp_server":
            if not holder.attr("_has_cloud_credentials"):
                continue
            families = _provider_families(holder.attr("_cloud_credential_keys"))
        elif holder.type == "k8s_container":
            families = sorted(
                set(holder.attr("_credential_providers") or []) & set(_PROVIDER_PREFIX)
            )
        else:
            continue
        for family in families:
            for target in cloud_by_family.get(family, [])[:_CREDENTIAL_REACH_CAP]:
                if target.id == holder.id:
                    continue
                model.edges.append(Edge(
                    source_id=holder.id,
                    target_id=target.id,
                    kind="credential_reach",
                    attributes={"provider": family, "via": "cloud credentials in env"},
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
