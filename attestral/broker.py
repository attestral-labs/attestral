"""Credential-broker remediation: strip a standing key, generate the JIT broker.

Detection tells you a server holds a standing, agent-readable credential
(ATL-104/110/112/115/164/168). This turns that into the fix: the exact env keys
to remove, and a CB4A Model A agentgateway broker route that mints a short-lived,
scoped token per call in their place, so the agent process never holds a reusable
key. It is the active-governor half of the credential rules - detect, then
generate the control that removes the standing credential rather than just
naming it.

The generated route mirrors `compile.render_agentgateway` (strict inbound auth,
per-call RFC 8693 token exchange, secret always by reference), but is scoped to
the specific servers that hold a standing credential today and carries an
intent-bound `scope` derived from the providers each server actually needs, so
the minted token is bound to the task, not a blanket grant. Terminal-first: the
plan prints; the broker config is written only with `-o`.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field

from attestral.ingest.mcp import _CLOUD_CRED_HINTS, _SECRET_HINTS, _credential_provider_families
from attestral.model import SystemModel

# The per-server credential findings whose root cause is a standing key in an
# mcp_server's env - the family `attestral fix` can close by stripping the keys
# and fronting the server with the generated broker route. Deliberately NOT
# ATL-110 (the credential is in argv, not env) and NOT ATL-221 (model-level: its
# fix IS the per-server strips these produce).
BROKER_FIX_RULES = frozenset({"ATL-104", "ATL-112", "ATL-115", "ATL-149", "ATL-164"})

# The token endpoint / OAuth host are environment-specific; emit obvious
# placeholders so the operator wires their own IdP and nothing runs by accident.
_IDP_HOST = "REPLACE_WITH_IDP_HOST:443"
_TOKEN_PATH = "/oauth2/v1/token"


@dataclass
class BrokerPlan:
    """One server's move from a standing credential to a brokered, per-call token."""
    component_id: str
    name: str
    stripped: list[str] = field(default_factory=list)   # secret env keys to remove
    providers: list[str] = field(default_factory=list)  # provider families to scope the token to
    cloud: bool = False                                  # holds cloud creds (wider blast)
    concentration: bool = False                          # >= 4 providers in one process


def _standing_env_keys(env_keys) -> list[str]:
    """The standing-credential env keys on a server - the keys to strip. The
    union of the ingester's own secret test (_SECRET_HINTS) and its cloud-cred
    test (_CLOUD_CRED_HINTS), because cloud keys like KUBECONFIG or
    AZURE_CLIENT_ID are standing credentials that carry no secret-shaped token.
    Mirrors the ingester so the two never disagree."""
    return sorted(
        str(k) for k in (env_keys or [])
        if any(h in str(k).upper() for h in _SECRET_HINTS + _CLOUD_CRED_HINTS)
    )


def _plan_for_component(c) -> BrokerPlan | None:
    """The broker plan for one mcp_server component, or None when it holds no
    standing credential in its env."""
    if not (c.attr("_env_has_secrets") or c.attr("_has_cloud_credentials")):
        return None
    stripped = _standing_env_keys(c.attr("env_keys"))
    if not stripped:
        return None
    return BrokerPlan(
        component_id=c.id, name=c.name, stripped=stripped,
        providers=list(c.attr("_credential_providers") or []),
        cloud=bool(c.attr("_has_cloud_credentials")),
        concentration=bool(c.attr("_credential_concentration")),
    )


def plan_for(model: SystemModel, component_id: str) -> BrokerPlan | None:
    """The broker plan for the named component, or None when it is not an
    mcp_server holding a standing credential."""
    c = model.get(component_id)
    if c is None or c.type != "mcp_server":
        return None
    return _plan_for_component(c)


def broker_plans(model: SystemModel) -> list[BrokerPlan]:
    """A plan for every MCP server that holds a standing credential in its env,
    ordered widest-blast-first (concentration, then cloud, then the rest)."""
    plans = [p for c in model.by_type("mcp_server") if (p := _plan_for_component(c))]
    plans.sort(key=lambda p: (not p.concentration, not p.cloud, p.name))
    return plans


def strip_standing_credentials(model: SystemModel, component_id: str) -> SystemModel:
    """A deep copy of the model with the component's standing-credential env keys
    removed and every env-derived credential attribute RE-DERIVED through the
    same classifiers the ingester used - not hand-cleared, so re-evaluating the
    rules over the copy is a real proof that the strip closes the finding.
    `_remote_unauthed` is deliberately left untouched: post-broker, inbound auth
    is the route's strict jwtAuth, so the env secret's disappearance does not
    make the endpoint unauthenticated."""
    m = copy.deepcopy(model)
    c = m.get(component_id)
    if c is None:
        return m
    stripped = set(_standing_env_keys(c.attr("env_keys")))
    kept = [k for k in (c.attr("env_keys") or []) if str(k) not in stripped]
    a = c.attributes
    a["env_keys"] = kept
    a["_env_has_secrets"] = any(
        any(h in str(k).upper() for h in _SECRET_HINTS) for k in kept
    )
    if c.attr("url"):
        a["_confused_deputy"] = bool(a["_env_has_secrets"])
    caps = set(c.attr("_capabilities") or [])
    if not (a["_env_has_secrets"] and caps & {"database", "memory", "saas_data"}):
        a.pop("_shared_static_credential", None)
    if not (a["_env_has_secrets"] and "memory" in caps):
        a.pop("_shared_memory_credential", None)
    cred = [k for k in kept if any(h in str(k).upper() for h in _CLOUD_CRED_HINTS)]
    a["_cloud_credential_keys"] = cred
    a["_has_cloud_credentials"] = bool(cred)
    providers = _credential_provider_families(kept)
    a["_credential_providers"] = providers
    a["_credential_concentration"] = len(providers) >= 4
    return m


def _scope(plan: BrokerPlan) -> str:
    """The intent-bound scope the broker mints the token with: one audience per
    provider the server actually needs, so the token is task-scoped, not blanket."""
    if plan.providers:
        return " ".join(f"provider:{p}" for p in plan.providers)
    return "REPLACE_WITH_LEAST_PRIVILEGE_SCOPE"


def _broker_route(plan: BrokerPlan) -> dict:
    """A CB4A Model A route: strict inbound auth + per-call token exchange, secret
    by reference, token scoped to the server's providers."""
    return {
        "name": plan.name,
        "policies": {"jwtAuth": {"mode": "strict"}},
        "backends": [{
            "mcp": {"name": plan.name},
            "backendAuth": {"oauthTokenExchange": {
                "host": _IDP_HOST,
                "tokenEndpointPath": _TOKEN_PATH,
                "scope": _scope(plan),
                "clientAuth": {
                    "clientId": f"attestral-{plan.name}",
                    "secretRef": {"name": f"{plan.name}-oauth-client"},
                },
            }},
        }],
    }


def render_broker_config(plans: list[BrokerPlan]) -> str:
    """The generated agentgateway broker config that replaces the standing
    credentials: one strict, token-exchanging route per credential-holding
    server. Default-deny by construction - a server not listed is not routable."""
    import yaml

    routes = [_broker_route(p) for p in plans]
    config = {"binds": [{"port": 3000, "listeners": [{"routes": routes}]}]}
    stripped_note = "\n".join(
        f"#   {p.name}: remove {', '.join(p.stripped)} from env; call through the broker"
        for p in plans
    )
    header = (
        "# agentgateway credential-broker config - GENERATED BY `attestral broker`.\n"
        "# It replaces the standing credentials below with a per-call, scoped token\n"
        "# (CB4A Model A, RFC 8693 token exchange). After deploying it:\n"
        f"{stripped_note}\n"
        "# Fill REPLACE_WITH_IDP_HOST and the client secretRefs for your IdP. The\n"
        "# agent then holds no reusable key; the broker mints a scoped token per call.\n"
    )
    return header + yaml.safe_dump(config, sort_keys=False)


def render_broker_plan(model: SystemModel, *, color: bool | None = None) -> str:
    """Terminal-first remediation: which servers hold a standing credential, the
    exact keys to strip, and the brokered, scoped token that replaces them."""
    from attestral.report_terminal import _bold, _dim, _paint, supports_color

    if color is None:
        color = supports_color()
    plans = broker_plans(model)
    if not plans:
        return _paint("No standing credentials to broker: no MCP server holds a "
                      "secret in its environment.", "32", color)

    n_keys = sum(len(p.stripped) for p in plans)
    lines = [_paint(
        f"Credential-broker remediation ({len(plans)} server(s), "
        f"{n_keys} standing credential(s) to strip)", "1;31", color)]
    for p in plans:
        tag = ""
        if p.concentration:
            tag = _paint("  [concentration: 4+ providers]", "1;31", color)
        elif p.cloud:
            tag = _paint("  [cloud credential]", "33", color)
        lines.append("")
        lines.append(f"  {_bold(p.name, color)}{tag}")
        lines.append(f"    {_dim('strip: ', color)}{', '.join(p.stripped)}")
        if p.providers:
            lines.append(f"    {_dim('scope: ', color)}"
                         f"{', '.join(p.providers)} (token bound to these providers)")
        lines.append(f"    {_dim('replace:', color)} per-call brokered token via "
                     f"agentgateway route '{p.name}' (strict auth, no standing key)")
    lines.append("")
    lines.append(_dim("Write the generated broker config with -o; deploy it, then "
                      "remove the stripped keys from each server's environment.", color))
    return "\n".join(lines)
