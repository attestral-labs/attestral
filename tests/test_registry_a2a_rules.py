"""Coverage for the ingester-surface wave: ATL-129..133.

Two surfaces:
  * agent_config.py A2A card ingester gains signature + OAuth-flow awareness
    (`_uses_removed_oauth_flow`, `_public_unsigned`) -> ATL-129 / ATL-130.
  * mcp.py gains an MCP Registry `server.json` ingester emitting
    `mcp_registry_manifest` components -> ATL-131 / ATL-132 / ATL-133.
Each rule fires on its fixture and stays silent when the signal is absent.
"""
from attestral.ingest import build_model
from attestral.ingest.agent_config import ingest_agent_config
from attestral.ingest.mcp import ingest_registry, registry_component_from_manifest
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

A2A = "examples/a2a-hardening"
REGISTRY = "examples/mcp-registry"




# --- ATL-129 / ATL-130: A2A card hardening --------------------------------

def test_removed_oauth_flow_fires_atl129():
    assert "ATL-129" in ids_for(A2A)


def test_public_unsigned_card_fires_atl130():
    assert "ATL-130" in ids_for(A2A)


def test_a2a_hardening_attrs_surfaced():
    model = build_model(A2A)
    card = next(iter(model.by_type("a2a_agent")))
    assert card.attr("_uses_removed_oauth_flow") is True
    assert "implicit" in (card.attr("_removed_oauth_flows") or [])
    assert card.attr("_has_signature") is False
    assert card.attr("_public_unsigned") is True


def test_signed_card_with_modern_flow_is_silent(tmp_path):
    d = tmp_path / ".well-known"
    d.mkdir()
    (d / "agent-card.json").write_text(
        '{"name": "ok", "url": "https://ok.example/a2a",'
        ' "security": [{"oauth": ["read"]}],'
        ' "securitySchemes": {"oauth": {"type": "oauth2",'
        ' "flows": {"authorizationCode": {"authorizationUrl": "https://ok.example/a",'
        ' "tokenUrl": "https://ok.example/t", "scopes": {}}}}},'
        ' "signatures": [{"protected": "e30", "signature": "abc"}]}'
    )
    model = ingest_agent_config(tmp_path, SystemModel())
    card = next(iter(model.by_type("a2a_agent")))
    assert card.attr("_uses_removed_oauth_flow") is False
    assert card.attr("_public_unsigned") is False
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-129" not in ids and "ATL-130" not in ids


# --- ATL-131 / ATL-132 / ATL-133: registry manifest -----------------------

def test_hardcoded_secret_fires_atl131():
    assert "ATL-131" in ids_for(REGISTRY)


def test_unmarked_secret_fires_atl132():
    assert "ATL-132" in ids_for(REGISTRY)


def test_deprecated_sse_transport_fires_atl133():
    assert "ATL-133" in ids_for(REGISTRY)


def test_registry_manifest_partitions_vars():
    model = build_model(REGISTRY)
    m = next(iter(model.by_type("mcp_registry_manifest")))
    assert "DATA_BRIDGE_API_KEY" in (m.attr("_hardcoded_secret_vars") or [])
    assert "DATABASE_PASSWORD" in (m.attr("_unmarked_secret_vars") or [])
    # LOG_LEVEL is neither hardcoded-secret nor unmarked-secret.
    assert "LOG_LEVEL" not in (m.attr("_hardcoded_secret_vars") or [])
    assert "LOG_LEVEL" not in (m.attr("_unmarked_secret_vars") or [])


def test_clean_manifest_is_silent(tmp_path):
    f = tmp_path / "server.json"
    f.write_text(
        '{"name": "io.github.acme/clean", "packages": [{"registryType": "npm",'
        ' "identifier": "clean-mcp", "version": "1.0.0",'
        ' "transport": {"type": "stdio"},'
        ' "environmentVariables": [{"name": "API_TOKEN", "isSecret": true}]}]}'
    )
    model = ingest_registry(f, SystemModel())
    m = next(iter(model.by_type("mcp_registry_manifest")))
    assert m.attr("_has_hardcoded_secret") is False
    assert m.attr("_has_unmarked_secret") is False  # API_TOKEN is properly marked
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert not ({"ATL-131", "ATL-132", "ATL-133"} & ids)


def test_unrelated_server_json_is_not_a_manifest(tmp_path):
    # A file named server.json that is not an MCP registry manifest is ignored.
    f = tmp_path / "server.json"
    f.write_text('{"port": 8080, "host": "0.0.0.0"}')
    assert registry_component_from_manifest({"port": 8080}, str(f)) is None
    model = ingest_registry(f, SystemModel())
    assert not list(model.by_type("mcp_registry_manifest"))
