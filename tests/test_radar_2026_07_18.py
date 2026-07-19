"""Research radar 2026-07-18 wave.

New rules:
  ATL-147  MCP server binds 0.0.0.0 (all interfaces)
  ATL-148  MCP server forwards the caller's session token / auth header
  ATL-069  EC2 launch template still allows IMDSv1
  ATL-338  AKS local accounts enabled
Enhanced:
  ATL-133  deprecated transport now also matches websocket / ws

Every positive asserts the id fires on a fixture; every mechanism ships a
negative that proves it stays silent when the signal is absent.
"""
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp, registry_component_from_manifest
from attestral.model import SystemModel
from attestral.rules import RuleEngine


def _ids(path: str) -> set[str]:
    return {f.rule_id for f in RuleEngine().evaluate(build_model(path))}


def _ids_model(model: SystemModel) -> set[str]:
    return {f.rule_id for f in RuleEngine().evaluate(model)}


# --- ATL-147: bind to all interfaces ---------------------------------------

def test_bind_all_fires_atl147():
    ids = _ids("examples/mcp-bind-all")
    assert "ATL-147" in ids


def test_bind_all_only_flags_the_exposed_server():
    model = build_model("examples/mcp-bind-all")
    findings = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-147"]
    flagged = {f.component_id for f in findings}
    assert flagged == {"mcp_server.metrics-server"}


def test_localhost_and_stdio_servers_do_not_fire_atl147(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {'
        '"loop": {"command": "node", "args": ["s.js", "--host", "127.0.0.1"]},'
        '"stdio": {"command": "node", "args": ["s.js"]}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    assert "ATL-147" not in _ids_model(model)


# --- ATL-148: token / session passthrough ----------------------------------

def test_token_passthrough_fires_atl148():
    ids = _ids("examples/mcp-token-passthrough")
    assert "ATL-148" in ids


def test_passthrough_only_flags_the_gateway():
    model = build_model("examples/mcp-token-passthrough")
    findings = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-148"]
    assert {f.component_id for f in findings} == {"mcp_server.api-gateway"}


def test_generic_secret_env_is_atl104_not_atl148(tmp_path):
    # A server holding its OWN downstream API key is ATL-104's job. It carries no
    # forwarded-token key name, so the passthrough rule must stay silent.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"svc": {"command": "node", "args": ["s.js"],'
        ' "env": {"STRIPE_API_KEY": "sk_live_x"}}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    ids = _ids_model(model)
    assert "ATL-104" in ids
    assert "ATL-148" not in ids


# --- ATL-069: launch-template IMDSv1 ---------------------------------------

def test_launch_template_imdsv1_fires_atl069():
    ids = _ids("examples/aws-launch-template")
    assert "ATL-069" in ids


def test_launch_template_only_flags_the_optional_one():
    model = build_model("examples/aws-launch-template")
    findings = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-069"]
    assert {f.component_id for f in findings} == {"aws_launch_template.workers"}


def test_hardened_launch_template_not_flagged(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_launch_template" "ok" {\n'
        '  metadata_options {\n'
        '    http_tokens = "required"\n'
        "  }\n}\n"
    )
    assert "ATL-069" not in _ids(str(tmp_path))


# --- ATL-338: AKS local accounts -------------------------------------------

def test_aks_local_accounts_fires_atl338():
    ids = _ids("examples/aks-local-accounts")
    assert "ATL-338" in ids


def test_aks_only_flags_the_local_account_cluster():
    model = build_model("examples/aks-local-accounts")
    findings = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-338"]
    assert {f.component_id for f in findings} == {"azurerm_kubernetes_cluster.prod"}


def test_aks_local_accounts_disabled_not_flagged(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "azurerm_kubernetes_cluster" "ok" {\n'
        "  local_account_disabled = true\n}\n"
    )
    assert "ATL-338" not in _ids(str(tmp_path))


# --- ATL-133: deprecated transport broadened to websocket ------------------

def _manifest(transport_type: str) -> dict:
    return {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.json",
        "name": "io.example/ws-bridge",
        "remotes": [{"type": transport_type, "url": "wss://example/mcp"}],
    }


def test_websocket_transport_fires_atl133():
    comp = registry_component_from_manifest(_manifest("websocket"), "server.json")
    assert comp is not None
    assert "websocket" in comp.attr("_deprecated_transports")
    model = SystemModel()
    model.add(comp)
    assert "ATL-133" in _ids_model(model)


def test_ws_transport_fires_atl133():
    comp = registry_component_from_manifest(_manifest("ws"), "server.json")
    model = SystemModel()
    model.add(comp)
    assert "ATL-133" in _ids_model(model)


def test_streamable_http_transport_not_flagged():
    comp = registry_component_from_manifest(_manifest("streamable-http"), "server.json")
    assert comp.attr("_deprecated_transports") == []
    model = SystemModel()
    model.add(comp)
    assert "ATL-133" not in _ids_model(model)
