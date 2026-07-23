"""Rule coverage for the MCP Apps UI wave: ATL-160/161/162 (per-server) and
ATL-220 (fleet-level private-data + ui_egress pairing).

Positives ride the examples/mcp-apps-ui and examples/mcp-apps-ui-fleet
fixtures; negatives pin the fail-closed edges - the default-safe CSP server
fires nothing, tasks without auto-approve is a feature not a finding, and UI
egress with no private-data capability anywhere never trips the fleet rule.
Ingest-surface assertions live in test_mcp_apps_ui_ingest.py.
"""
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine

from _helpers import findings_for, ids_for

FIXTURE = "examples/mcp-apps-ui"
FLEET_FIXTURE = "examples/mcp-apps-ui-fleet"


def _ids_from_json(tmp_path, servers_json: str) -> set[str]:
    cfg = tmp_path / "mcp.json"
    cfg.write_text(servers_json)
    model = ingest_mcp(cfg, SystemModel())
    return {f.rule_id for f in RuleEngine().evaluate(model)}


# --- positives ---------------------------------------------------------------

def test_ui_wave_rules_fire():
    assert {"ATL-160", "ATL-161", "ATL-162"} <= ids_for(FIXTURE)


def test_external_connect_fires_atl160_on_the_ui_server():
    findings = findings_for(FIXTURE)
    assert any(
        f.rule_id == "ATL-160" and f.component_id == "mcp_server.dash-widgets"
        for f in findings
    )


def test_sensitive_permissions_fire_atl161_on_the_ui_server():
    findings = findings_for(FIXTURE)
    assert any(
        f.rule_id == "ATL-161" and f.component_id == "mcp_server.dash-widgets"
        for f in findings
    )


def test_tasks_plus_auto_approve_fires_atl162():
    findings = findings_for(FIXTURE)
    assert any(
        f.rule_id == "ATL-162" and f.component_id == "mcp_server.auto-pipeline"
        for f in findings
    )


def test_fleet_private_data_plus_ui_egress_fires_atl220():
    # project-files contributes `filesystem`, report-widgets contributes
    # `ui_egress`: only the assembled model sees the pairing.
    assert {"ATL-160", "ATL-220"} <= ids_for(FLEET_FIXTURE)


# --- negatives ---------------------------------------------------------------

def test_default_safe_csp_server_fires_nothing():
    # local-preview declares a UI resource with the spec-default CSP
    # (connectDomains absent = 'none') and no permissions: zero findings.
    findings = findings_for(FIXTURE)
    assert not [f for f in findings if f.component_id == "mcp_server.local-preview"]


def test_tasks_without_auto_approve_does_not_fire_atl162():
    # task-runner negotiates the tasks extension but keeps the human
    # checkpoint: background tasks alone are a feature, not a finding.
    findings = findings_for(FIXTURE)
    assert not [f for f in findings if f.component_id == "mcp_server.task-runner"]


def test_auto_approve_without_tasks_does_not_fire_atl162(tmp_path):
    # The other half of the ATL-162 conjunction: auto-approve alone is
    # ATL-108's finding, never ATL-162's.
    ids = _ids_from_json(tmp_path, (
        '{"mcpServers": {"eager": {"command": "npx", "args": ["eager-mcp@1.0.0"],'
        ' "autoApprove": ["do_thing"]}}}'
    ))
    assert "ATL-108" in ids
    assert "ATL-162" not in ids


def test_ui_egress_without_private_data_does_not_fire_atl220():
    # dash-widgets carries ui_egress, but no server in the fixture holds a
    # filesystem/database/saas_data/memory capability: the pairing is absent.
    assert "ATL-220" not in ids_for(FIXTURE)


def test_own_host_and_loopback_connect_domains_do_not_fire_atl160(tmp_path):
    # Loopback origins and the server's own host are not external egress.
    ids = _ids_from_json(tmp_path, (
        '{"mcpServers": {"hosted": {"url": "https://widgets.example.com/mcp",'
        ' "resources": [{"uri": "ui://hosted/p", "_meta":'
        ' {"io.modelcontextprotocol/ui": {"connectDomains":'
        ' ["http://localhost:8080", "https://widgets.example.com"]}}}]}}}'
    ))
    assert "ATL-160" not in ids


def test_non_sensitive_permissions_do_not_fire_atl161(tmp_path):
    # A benign sandbox grant (e.g. notifications) is not a sensor/clipboard
    # permission; attr_list_any_of stays silent when the attr is absent.
    ids = _ids_from_json(tmp_path, (
        '{"mcpServers": {"widgety": {"command": "npx", "args": ["w-mcp@1.0.0"],'
        ' "resources": [{"uri": "ui://w/p", "_meta":'
        ' {"io.modelcontextprotocol/ui": {"permissions": {"notifications": {}}}}}]}}}'
    ))
    assert "ATL-161" not in ids
