"""Ingest deployment env surfaces (docker-compose services and .env files) for
credential concentration.

A holistic sweep of 390 popular MCP repos found the LiteLLM-class concentration
pattern in zero committed .mcp.json files, because committed configs do not ship
provider keys in env - the deployment does. ATL-164 catches it in an MCP config
and ATL-165 in a Kubernetes workload; this ingester catches it in the two most
common deployment surfaces a small team actually uses: a `docker-compose.yml`
service and a `.env` file. Each surface becomes a `deployment_env` component
carrying the same `_credential_providers` signal the MCP layer emits, so a
gateway holding five providers' keys is flagged the same way wherever it lands.
"""
from __future__ import annotations

from pathlib import Path

import yaml

from attestral.ingest.mcp import _credential_provider_families
from attestral.model import Component, SystemModel

_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
# .env variants that carry real values. Templates (.example/.sample/.template) are
# skipped: they document the shape but are not the deployment's actual key set.
_DOTENV_SKIP = (".example", ".sample", ".template", ".dist")


def _component(kind: str, name: str, source: str, env_names: list[str]) -> Component | None:
    providers = _credential_provider_families(env_names)
    if not providers:
        return None  # nothing credential-shaped here; not a surface worth a component
    return Component(
        id=f"deployment_env.{kind}.{name}",
        type="deployment_env",
        name=name,
        source=source,
        attributes={
            "_surface": kind,
            "_credential_providers": providers,
            "_credential_concentration": len(providers) >= 4,
        },
        trust_boundary="agent_runtime",
    )


def _compose_env_names(service: dict) -> list[str]:
    """Env var names from a compose service's `environment`, dict or list form."""
    env = service.get("environment")
    names: list[str] = []
    if isinstance(env, dict):
        names = [str(k) for k in env]
    elif isinstance(env, list):
        for item in env:
            s = str(item)
            names.append(s.split("=", 1)[0] if "=" in s else s)
    return names


def _ingest_compose(f: Path, model: SystemModel) -> None:
    try:
        doc = yaml.safe_load(f.read_text(errors="ignore"))
    except (yaml.YAMLError, OSError):
        return
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return
    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        comp = _component("compose", str(name), str(f), _compose_env_names(service))
        if comp is not None:
            model.add(comp)


def _dotenv_names(f: Path) -> list[str]:
    names: list[str] = []
    try:
        text = f.read_text(errors="ignore")
    except OSError:
        return names
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue
        names.append(line.split("=", 1)[0].strip())
    return names


def _ingest_dotenv(f: Path, model: SystemModel) -> None:
    if any(f.name.endswith(skip) for skip in _DOTENV_SKIP):
        return
    comp = _component("dotenv", f.name, str(f), _dotenv_names(f))
    if comp is not None:
        model.add(comp)


def ingest_deployment_env(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    if p.is_file():
        files = [p]
    else:
        files = sorted(
            [q for q in p.rglob("*") if q.is_file() and (
                q.name in _COMPOSE_NAMES or q.name == ".env" or q.name.startswith(".env.")
            )]
        )
    for f in files:
        if f.name in _COMPOSE_NAMES:
            _ingest_compose(f, model)
        else:
            _ingest_dotenv(f, model)
    return model
