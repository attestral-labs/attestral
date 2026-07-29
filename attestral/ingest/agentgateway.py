"""Ingest agentgateway credential-broker configuration.

agentgateway (Solo.io, Agentic AI Foundation) implements the CB4A Model A proxy
gateway: it fronts a backend, injects the real credential on egress via RFC 8693
token exchange, and the agent never holds a reusable key. This ingester reviews
whether a *declared* gateway actually delivers that guarantee, the second job the
CB4A draft frames for a design review (job b: does the broker really eliminate
the standing credential, or is it a Model C in disguise).

Two shapes are recognized, both fail-closed on anything unexpected:
  - the Kubernetes CRD  (`kind: AgentgatewayPolicy`, `agentgateway.dev/*`) whose
    `spec.backend.auth` carries `oauthTokenExchange` / `crossAppAccess`;
  - the standalone config (`binds: [...]`) whose routes carry inbound `jwtAuth`
    and per-backend `backendAuth.oauthTokenExchange`.

Each route becomes an `agentgateway_route` component. Attributes are the signals
the rules key on; nothing here executes or contacts an endpoint.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from attestral.model import Component, SystemModel

# A file is worth parsing as agentgateway config only if one of these markers is
# present. Cheap text pre-filter before the YAML load, same idea as the k8s one.
_MARKERS = ("agentgateway.dev", "AgentgatewayPolicy", "backendAuth",
            "oauthTokenExchange", "crossAppAccess")

# Placeholder client-secret values that are not a real inlined credential.
_SECRET_PLACEHOLDERS = ("${", "$(", "changeme", "redacted", "your-", "<", "example")


def _is_inline_secret(client_auth: dict) -> bool:
    """True when clientAuth carries a literal clientSecret instead of a secretRef.
    An env reference (`${VAR}`) or an obvious placeholder is the correct pattern
    and never counts, so a sanitized example config is not flagged."""
    if not isinstance(client_auth, dict):
        return False
    if client_auth.get("secretRef"):
        return False
    secret = client_auth.get("clientSecret")
    if not isinstance(secret, str) or not secret.strip():
        return False
    low = secret.strip().lower()
    return not any(ph in low for ph in _SECRET_PLACEHOLDERS)


def _backend_auth_of(backend: dict) -> dict | None:
    """The credential-brokering block on a backend, either config shape."""
    if not isinstance(backend, dict):
        return None
    # standalone: backends[].backendAuth ; CRD: spec.backend.auth
    return backend.get("backendAuth") or backend.get("auth") or None


def _route_component(name: str, source: str, *, brokered: bool, inline_secret: bool,
                     inbound_declared: bool, inbound_strict: bool) -> Component:
    # Fail-open when a route brokers a credential to a backend but its inbound
    # side is not strictly authenticated: an unauthenticated caller reaches a
    # credentialed egress (CB4A TM-9). Only meaningful when inbound auth is even
    # expressible (the standalone form), so the CRD form leaves it False.
    fail_open = inbound_declared and not inbound_strict
    return Component(
        id=f"agentgateway_route.{name}",
        type="agentgateway_route",
        name=name,
        source=source,
        attributes={
            "_brokers_credential": brokered,
            "_inline_client_secret": inline_secret,
            "_inbound_auth_declared": inbound_declared,
            "_inbound_auth_strict": inbound_strict,
            "_fail_open": fail_open,
        },
        trust_boundary="agent_runtime",
    )


def _ingest_crd(doc: dict, source: str, model: SystemModel) -> None:
    spec = doc.get("spec") if isinstance(doc.get("spec"), dict) else {}
    backend = spec.get("backend") if isinstance(spec.get("backend"), dict) else {}
    auth = _backend_auth_of(backend) or _backend_auth_of(spec) or {}
    brokered = bool(auth.get("oauthTokenExchange") or auth.get("crossAppAccess"))
    exchange = auth.get("oauthTokenExchange") if isinstance(auth.get("oauthTokenExchange"), dict) else {}
    inline = _is_inline_secret(exchange.get("clientAuth") or {})
    name = (doc.get("metadata") or {}).get("name") or "policy"
    model.add(_route_component(name, source, brokered=brokered, inline_secret=inline,
                               inbound_declared=False, inbound_strict=False))


def _jwt_strict(policies: dict) -> tuple[bool, bool]:
    """(declared, strict) for a route's inbound jwtAuth."""
    jwt = policies.get("jwtAuth") if isinstance(policies, dict) else None
    if not isinstance(jwt, dict):
        return (False, False)
    return (True, str(jwt.get("mode", "")).lower() == "strict")


def _ingest_standalone(doc: dict, source: str, model: SystemModel) -> None:
    binds = doc.get("binds")
    if not isinstance(binds, list):
        return
    for bi, bind in enumerate(binds):
        if not isinstance(bind, dict):
            continue
        for listener in bind.get("listeners") or []:
            if not isinstance(listener, dict):
                continue
            for ri, route in enumerate(listener.get("routes") or []):
                if not isinstance(route, dict):
                    continue
                declared, strict = _jwt_strict(route.get("policies") or {})
                brokered = False
                inline = False
                for backend in route.get("backends") or []:
                    ba = _backend_auth_of(backend) or {}
                    if ba.get("oauthTokenExchange") or ba.get("crossAppAccess"):
                        brokered = True
                    ex = ba.get("oauthTokenExchange") if isinstance(ba.get("oauthTokenExchange"), dict) else {}
                    if _is_inline_secret(ex.get("clientAuth") or {}):
                        inline = True
                # Only model a route that actually fronts a backend; a bare
                # listener with no backend is not a credential-broker surface.
                if not (route.get("backends") or brokered):
                    continue
                name = route.get("name") or f"bind{bi}-route{ri}"
                model.add(_route_component(name, source, brokered=brokered,
                                           inline_secret=inline,
                                           inbound_declared=declared, inbound_strict=strict))


def ingest_agentgateway(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    files = [p] if p.is_file() else sorted(
        list(p.rglob("*.yaml")) + list(p.rglob("*.yml"))
    )
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        if not any(m in text for m in _MARKERS):
            continue
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            continue
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            api = str(doc.get("apiVersion", ""))
            if doc.get("kind") == "AgentgatewayPolicy" or "agentgateway.dev" in api:
                _ingest_crd(doc, str(f), model)
            elif isinstance(doc.get("binds"), list):
                _ingest_standalone(doc, str(f), model)
    return model
