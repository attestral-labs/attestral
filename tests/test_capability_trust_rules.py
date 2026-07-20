"""Coverage for the MCP capability-abuse + coding-agent-trust wave: ATL-125..128.

Two ingester signals feed these rules:
  * mcp.py surfaces `_declared_capabilities` (real protocol capabilities a
    server config declares - sampling / elicitation), distinct from the coarse
    `_capabilities` reachability set.
  * agent_config.py surfaces `_bypass_permissions` / `_auto_enable_project_mcp`
    from a committed `.claude/settings.json`.
Each rule must fire on its fixture and stay silent when the signal is absent.
"""
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.ingest.agent_config import ingest_agent_config
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

CAPS = "examples/mcp-capabilities"
TRUST = "examples/coding-agent-trust"




# --- ATL-125 / ATL-126: declared MCP capabilities -------------------------

def test_sampling_capability_fires_atl125():
    assert "ATL-125" in ids_for(CAPS)


def test_elicitation_capability_fires_atl126():
    assert "ATL-126" in ids_for(CAPS)


def test_declared_capabilities_surfaced_on_component():
    model = build_model(CAPS)
    bridge = model.get("mcp_server.assistant-bridge")
    intake = model.get("mcp_server.intake")
    assert "sampling" in (bridge.attr("_declared_capabilities") or [])
    assert "elicitation" in (intake.attr("_declared_capabilities") or [])


def test_server_without_declared_capabilities_is_silent(tmp_path):
    # No `capabilities` key -> attribute unset -> neither capability rule fires.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"plain": {"command": "npx", "args": ["some-mcp"]}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.plain").attr("_declared_capabilities") is None
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-125" not in ids and "ATL-126" not in ids


def test_capability_declared_false_does_not_fire(tmp_path):
    # A capability explicitly disabled (value False) is not "declared".
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"s": {"command": "npx", "args": ["x"],'
        ' "capabilities": {"sampling": false}}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    assert "sampling" not in (model.get("mcp_server.s").attr("_declared_capabilities") or [])
    assert "ATL-125" not in {f.rule_id for f in RuleEngine().evaluate(model)}


# --- ATL-127 / ATL-128: coding-agent trust switches -----------------------

def test_permission_bypass_fires_atl127():
    assert "ATL-127" in ids_for(TRUST)


def test_auto_enable_project_mcp_fires_atl128():
    assert "ATL-128" in ids_for(TRUST)


def test_trust_flags_surfaced_on_component():
    model = build_model(TRUST)
    cfg = next(iter(model.by_type("agent_config")))
    assert cfg.attr("_bypass_permissions") is True
    assert cfg.attr("_auto_enable_project_mcp") is True


def test_default_settings_do_not_fire(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    (d / "settings.json").write_text(
        '{"permissions": {"defaultMode": "default", "allow": []}}'
    )
    model = ingest_agent_config(tmp_path, SystemModel())
    cfg = next(iter(model.by_type("agent_config")))
    assert cfg.attr("_bypass_permissions") is False
    assert cfg.attr("_auto_enable_project_mcp") is False
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-127" not in ids and "ATL-128" not in ids
