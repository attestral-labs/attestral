"""Coverage for ATL-176: an unauthenticated, network-exposed MCP server that
grants command execution (the RufRoot class, CVE-2026-59726, CVSS 10.0).

The finding is the conjunction of three facts about one server - remote
plaintext transport, no authentication, and a shell/exec capability - that only
the system model composes; each fixture counter-case drops exactly one leg and
must stay silent."""
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for, model_for

FIXTURE = "examples/rufroot-unauth-exec"


def test_unauth_exec_exposed_fires_atl176():
    # ops-bridge: plaintext http url, no auth, bash shell launch -> all three legs.
    assert "ATL-176" in ids_for(FIXTURE)


def test_atl176_fires_on_exactly_the_rufroot_server():
    # ATL-176 must attribute to the one server that holds all three legs, not the
    # counter-cases that each drop one.
    findings = [f for f in RuleEngine().evaluate(model_for(FIXTURE)) if f.rule_id == "ATL-176"]
    assert {f.component_id for f in findings} == {"mcp_server.ops-bridge"}


def test_rufroot_server_has_both_legs_derived():
    model = model_for(FIXTURE)
    ops = model.get("mcp_server.ops-bridge")
    assert ops.attr("_remote_unauthed") is True
    assert "shell" in (ops.attr("_capabilities") or [])


def test_stdio_exec_server_is_not_network_exposed(tmp_path):
    # A local stdio shell server (no url) drops the network leg: ATL-176 silent,
    # even though it is genuinely shell-capable (ATL-103 still fires).
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"local": {"command": "bash", "args": ["-lc", "mcp-shell"]}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    local = model.get("mcp_server.local")
    assert local.attr("_remote_unauthed") is None
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-176" not in ids
    assert "ATL-103" in ids


def test_authenticated_remote_exec_does_not_fire(tmp_path):
    # A network-reachable shell bridge that carries an auth header is
    # authenticated: the missing-auth leg is absent, so ATL-176 must not fire.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"bridge": {"command": "bash", "args": ["-lc", "mcp-bridge"],'
        ' "url": "http://bridge.example.net:3001/mcp",'
        ' "headers": {"Authorization": "${TOKEN}"}}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    bridge = model.get("mcp_server.bridge")
    assert bridge.attr("_remote_unauthed") is False
    assert "ATL-176" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_unauth_remote_readonly_does_not_fire(tmp_path):
    # An unauthenticated plaintext-http server with no execution capability drops
    # the exec leg: ATL-109 fires, ATL-176 does not.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"docs": {"url": "http://docs.example.net:8080/mcp"}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    docs = model.get("mcp_server.docs")
    assert docs.attr("_remote_unauthed") is True
    assert "shell" not in (docs.attr("_capabilities") or [])
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-176" not in ids
    assert "ATL-109" in ids


def test_https_unauthed_exec_does_not_fire(tmp_path):
    # A TLS endpoint carries no static credential per the MCP OAuth flow, so its
    # absence is expected and _remote_unauthed stays off - ATL-176 must not fire
    # on an https exec bridge (this is the OAuth-per-spec precision, not a miss).
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"tls": {"command": "bash", "args": ["-lc", "mcp-bridge"],'
        ' "url": "https://bridge.example.net/mcp"}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.tls").attr("_remote_unauthed") is False
    assert "ATL-176" not in {f.rule_id for f in RuleEngine().evaluate(model)}
