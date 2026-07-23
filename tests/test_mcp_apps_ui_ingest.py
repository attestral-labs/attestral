"""MCP Apps UI + extensions ingest surface (ext-apps 2026-01-26 / SEP-1865,
extensions map SEP-2663).

Asserts the ingester-derived attributes on the examples/mcp-apps-ui fixture:
the CSP-style UI declarations (connectDomains, permissions), the declared
extensions map, and the ui_egress capability token the fleet combos key on -
positive AND the default-safe-CSP negative. Attribute assertions only; rules
consuming these attributes are rules-wave-owner's side of the seam.
"""
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel

FIXTURE = "examples/mcp-apps-ui"


def _ingest(tmp_path, servers_json: str):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(servers_json)
    return ingest_mcp(cfg, SystemModel())


def test_ui_connect_domains_unioned():
    model = build_model(FIXTURE)
    srv = model.get("mcp_server.dash-widgets")
    assert srv is not None
    assert srv.attr("_ui_connect_domains") == [
        "https://*.cdn-metrics.io",
        "https://telemetry.example.net",
    ]


def test_external_connect_derives_flag_and_ui_egress_token():
    model = build_model(FIXTURE)
    srv = model.get("mcp_server.dash-widgets")
    assert srv.attr("_ui_external_connect") is True
    assert "ui_egress" in (srv.attr("_capabilities") or [])


def test_ui_permissions_and_sensitive_subset():
    model = build_model(FIXTURE)
    srv = model.get("mcp_server.dash-widgets")
    assert srv.attr("_ui_permissions") == ["camera", "clipboardWrite"]
    assert srv.attr("_ui_sensitive_permissions") == ["camera", "clipboardWrite"]


def test_default_safe_csp_derives_no_egress():
    # local-preview declares a UI resource but no connectDomains: the spec
    # default is 'none', so no connect attribute, no external flag, and no
    # ui_egress capability token may appear.
    model = build_model(FIXTURE)
    srv = model.get("mcp_server.local-preview")
    assert srv is not None
    assert srv.attr("_ui_connect_domains") is None
    assert srv.attr("_ui_external_connect") is None
    assert srv.attr("_ui_sensitive_permissions") is None
    assert "ui_egress" not in (srv.attr("_capabilities") or [])


def test_declared_extensions_map():
    model = build_model(FIXTURE)
    srv = model.get("mcp_server.task-runner")
    assert srv.attr("_declared_extensions") == ["io.modelcontextprotocol/tasks"]
    # A server declaring no extensions derives nothing.
    assert model.get("mcp_server.dash-widgets").attr("_declared_extensions") is None


def test_legacy_tasks_capability_normalizes(tmp_path):
    model = _ingest(tmp_path, (
        '{"mcpServers": {"legacy": {"command": "npx", "args": ["x-mcp@1.0.0"],'
        ' "capabilities": {"tasks": {}}}}}'
    ))
    srv = model.get("mcp_server.legacy")
    assert srv.attr("_declared_extensions") == ["io.modelcontextprotocol/tasks"]


def test_legacy_bare_ui_meta_key_accepted(tmp_path):
    model = _ingest(tmp_path, (
        '{"mcpServers": {"old": {"command": "npx", "args": ["old-mcp@1.0.0"],'
        ' "resources": [{"uri": "ui://old/p", "_meta":'
        ' {"ui": {"connectDomains": ["https://sink.example.org"]}}}]}}}'
    ))
    srv = model.get("mcp_server.old")
    assert srv.attr("_ui_connect_domains") == ["https://sink.example.org"]
    assert srv.attr("_ui_external_connect") is True


def test_loopback_and_own_host_are_not_external(tmp_path):
    # Loopback origins and the server's own url host are not declared egress.
    model = _ingest(tmp_path, (
        '{"mcpServers": {"hosted": {"url": "https://widgets.example.com/mcp",'
        ' "resources": [{"uri": "ui://hosted/p", "_meta":'
        ' {"io.modelcontextprotocol/ui": {"connectDomains":'
        ' ["http://localhost:8080", "https://[bad",'
        ' "https://widgets.example.com"]}}}]}}}'
    ))
    srv = model.get("mcp_server.hosted")
    # Domains are still recorded (the surface exists) ...
    assert srv.attr("_ui_connect_domains") == [
        "http://localhost:8080",
        "https://[bad",
        "https://widgets.example.com",
    ]
    # ... but none is external: loopback, unparseable (fails closed), own host.
    assert srv.attr("_ui_external_connect") is None
    assert "ui_egress" not in (srv.attr("_capabilities") or [])


def test_no_url_explicit_external_origin_still_counts(tmp_path):
    # A stdio server has no url to compare against: an explicit non-loopback
    # origin is still declared egress.
    model = _ingest(tmp_path, (
        '{"mcpServers": {"stdio": {"command": "npx", "args": ["s-mcp@1.0.0"],'
        ' "resources": [{"uri": "ui://s/p", "_meta":'
        ' {"io.modelcontextprotocol/ui": {"connectDomains":'
        ' ["https://collector.evil.example"]}}}]}}}'
    ))
    srv = model.get("mcp_server.stdio")
    assert srv.attr("_ui_external_connect") is True
    assert "ui_egress" in (srv.attr("_capabilities") or [])


def test_connect_domains_none_string_derives_nothing(tmp_path):
    model = _ingest(tmp_path, (
        '{"mcpServers": {"safe": {"command": "npx", "args": ["safe-mcp@1.0.0"],'
        ' "resources": [{"uri": "ui://safe/p", "_meta":'
        ' {"io.modelcontextprotocol/ui": {"connectDomains": "none",'
        ' "permissions": ["clipboard-write"]}}}]}}}'
    ))
    srv = model.get("mcp_server.safe")
    assert srv.attr("_ui_connect_domains") is None
    assert srv.attr("_ui_external_connect") is None
    # Permissions accepted as a plain list too; sensitive alias recognized.
    assert srv.attr("_ui_permissions") == ["clipboard-write"]
    assert srv.attr("_ui_sensitive_permissions") == ["clipboard-write"]


def test_malformed_ui_meta_never_crashes(tmp_path):
    # _meta not a dict, ui not a dict, connectDomains a number, permissions a
    # string: all fail closed - no UI attribute, no crash.
    model = _ingest(tmp_path, (
        '{"mcpServers": {"junk": {"command": "npx", "args": ["j-mcp@1.0.0"],'
        ' "resources": [{"uri": "ui://j/a", "_meta": "nope"},'
        ' {"uri": "ui://j/b", "_meta": {"io.modelcontextprotocol/ui": 7}},'
        ' {"uri": "ui://j/c", "_meta": {"io.modelcontextprotocol/ui":'
        ' {"connectDomains": 42, "permissions": "camera"}}}]}}}'
    ))
    srv = model.get("mcp_server.junk")
    assert srv is not None
    assert srv.attr("_ui_connect_domains") is None
    assert srv.attr("_ui_external_connect") is None
    assert srv.attr("_ui_permissions") is None
    assert srv.attr("_ui_sensitive_permissions") is None
