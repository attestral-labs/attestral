"""ATL-109 is OAuth-aware: it flags only a genuinely-exposed remote MCP server -
a non-loopback, plaintext http:// endpoint with no declared credential.

MCP's HTTP transports mandate OAuth 2.1 (MCP Security Best Practices, spec
revisions 2025-06-18 / 2025-11-25): the client obtains the bearer token through
an interactive flow at connect time, so a spec-compliant https:// hosted endpoint
legitimately carries NO static credential in the config. Flagging that absence
false-positives on every OAuth-gated hosted server. These tests pin the boundary:
TLS-with-no-static-token is expected (not flagged), plaintext-non-loopback is
open (flagged), loopback dev entries are not exposed (not flagged).
"""
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine


def _server(tmp_path, cfg_json: str, name: str):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(cfg_json)
    model = ingest_mcp(cfg, SystemModel())
    srv = model.get(f"mcp_server.{name}")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    return srv, ids


def test_https_remote_without_static_credential_is_oauth_expected(tmp_path):
    # A spec-compliant TLS endpoint (github's hosted MCP) obtains its OAuth
    # token interactively; the absence of a static credential here is expected.
    srv, ids = _server(
        tmp_path,
        '{"mcpServers": {"github": {"url": "https://api.githubcopilot.com/mcp/"}}}',
        "github",
    )
    assert srv.attr("_remote_unauthed") is False
    assert "ATL-109" not in ids


def test_wss_remote_without_static_credential_is_oauth_expected(tmp_path):
    # wss:// is TLS too: OAuth-expected, not a plaintext exposure.
    srv, ids = _server(
        tmp_path,
        '{"mcpServers": {"tls-ws": {"url": "wss://mcp.supabase.com/mcp"}}}',
        "tls-ws",
    )
    assert srv.attr("_remote_unauthed") is False
    assert "ATL-109" not in ids


def test_plaintext_nonloopback_remote_without_auth_fires(tmp_path):
    # A plaintext http endpoint is reachable by anyone on the path, and even an
    # OAuth token would cross the wire in cleartext: this is the open case.
    srv, ids = _server(
        tmp_path,
        '{"mcpServers": {"exposed": {"url": "http://mcp.internal.example.com:8080/"}}}',
        "exposed",
    )
    assert srv.attr("_remote_unauthed") is True
    assert "ATL-109" in ids


def test_plaintext_localhost_dev_entry_does_not_fire(tmp_path):
    # A loopback dev endpoint is not network-exposed, so it is exempt.
    srv, ids = _server(
        tmp_path,
        '{"mcpServers": {"dev": {"url": "http://localhost:3000/mcp"}}}',
        "dev",
    )
    assert srv.attr("_remote_unauthed") is False
    assert "ATL-109" not in ids


def test_plaintext_127_0_0_1_dev_entry_does_not_fire(tmp_path):
    srv, ids = _server(
        tmp_path,
        '{"mcpServers": {"dev": {"url": "http://127.0.0.1:9000/mcp"}}}',
        "dev",
    )
    assert srv.attr("_remote_unauthed") is False
    assert "ATL-109" not in ids


def test_plaintext_remote_with_auth_header_is_authenticated(tmp_path):
    # A declared inbound credential means the plaintext endpoint is not "open"
    # (its transport weakness is ATL-101's job, not ATL-109's).
    srv, ids = _server(
        tmp_path,
        '{"mcpServers": {"h": {"url": "http://mcp.internal.example.com/mcp",'
        ' "headers": {"Authorization": "Bearer x"}}}}',
        "h",
    )
    assert srv.attr("_remote_unauthed") is False
    assert "ATL-109" not in ids


def test_stdio_server_never_sets_remote_unauthed(tmp_path):
    # No url: the attribute is never emitted, so ATL-109 cannot match stdio.
    srv, ids = _server(
        tmp_path,
        '{"mcpServers": {"local": {"command": "npx", "args": ["some-mcp"]}}}',
        "local",
    )
    assert srv.attr("_remote_unauthed") is None
    assert "ATL-109" not in ids
