"""`attestral compile --target claude-managed` - the attested design as Claude
Code enterprise-managed MCP config.

Proves the two emitted files enforce the review: managed-mcp.json (exclusive
control) carries only the attested-allowed servers, so a denied server cannot
load on a managed machine, and managed-settings.json pins its allow/deny entries
to the launch identity (serverUrl/serverCommand), never the self-assigned
serverName the docs call out as not a security control.
"""
import json

from click.testing import CliRunner

from attestral.cli import main
from attestral.compile import compile_claude_managed, compile_policy
from attestral.ingest import build_model
from attestral.model import Component, SystemModel
from attestral.rules.engine import RuleEngine

FIXTURE = "examples/guard-runtime"


def _files():
    model = build_model(FIXTURE)
    policy = compile_policy(model, RuleEngine().evaluate(model))
    files = compile_claude_managed(model, policy)
    return (json.loads(files["managed-mcp.json"]),
            json.loads(files["managed-settings.json"]))


# -- managed-mcp.json: only the allowed server, as a loadable stdio entry --

def test_managed_mcp_carries_only_the_allowed_server():
    managed_mcp, _ = _files()
    servers = managed_mcp["mcpServers"]
    assert "docs" in servers and "root-files" not in servers  # denied cannot load
    assert servers["docs"]["type"] == "stdio"
    assert servers["docs"]["command"] == "npx"
    assert "/srv/docs" in servers["docs"]["args"]


# -- managed-settings.json: the default-deny toggle + launch-keyed lists --

def test_managed_settings_is_default_deny_and_hardened():
    _, settings = _files()
    assert settings["allowManagedMcpServersOnly"] is True
    assert settings["disableSideloadFlags"] is True


def test_allowlist_keys_on_launch_identity_never_servername():
    _, settings = _files()
    allow = settings["allowedMcpServers"]
    assert allow and all("serverName" not in e for e in allow)
    assert any(e.get("serverCommand", [])[:1] == ["npx"] for e in allow)


def test_denied_server_is_denylisted_by_command():
    _, settings = _files()
    denied = settings["deniedMcpServers"]
    # root-files carries a launch command, so it is denied by serverCommand
    # (precise), not by the weaker serverName fallback.
    assert any(e.get("serverCommand", [])[-1] == "/" for e in denied)


# -- a remote (url) server renders as an http entry + serverUrl match --

def _url_model_and_policy(allow: bool):
    model = SystemModel()
    model.add(Component(id="mcp_server.api", type="mcp_server", name="api",
                        source="cfg", attributes={"url": "https://api.example/mcp"},
                        trust_boundary="agent_runtime"))
    policy = {"servers": {"api": {"allow": allow}}}
    return model, policy


def test_remote_allowed_server_renders_http_and_serverurl():
    model, policy = _url_model_and_policy(allow=True)
    files = compile_claude_managed(model, policy)
    managed_mcp = json.loads(files["managed-mcp.json"])
    settings = json.loads(files["managed-settings.json"])
    assert managed_mcp["mcpServers"]["api"] == {"type": "http",
                                                "url": "https://api.example/mcp"}
    assert {"serverUrl": "https://api.example/mcp"} in settings["allowedMcpServers"]


def test_remote_denied_server_omitted_and_denylisted_by_url():
    model, policy = _url_model_and_policy(allow=False)
    files = compile_claude_managed(model, policy)
    managed_mcp = json.loads(files["managed-mcp.json"])
    settings = json.loads(files["managed-settings.json"])
    assert managed_mcp["mcpServers"] == {}
    assert {"serverUrl": "https://api.example/mcp"} in settings["deniedMcpServers"]


# -- empty design: managed-mcp.json disables MCP, allowlist is default-deny --

def test_no_servers_disables_mcp_and_denies_all():
    files = compile_claude_managed(SystemModel(), {"servers": {}})
    assert json.loads(files["managed-mcp.json"]) == {"mcpServers": {}}
    settings = json.loads(files["managed-settings.json"])
    assert settings["allowedMcpServers"] == []  # empty = no server allowed


# -- CLI writes both files --

def test_cli_writes_both_files(tmp_path):
    r = CliRunner().invoke(main, ["compile", FIXTURE, "--target", "claude-managed",
                                  "-o", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert (tmp_path / "managed-mcp.json").exists()
    assert (tmp_path / "managed-settings.json").exists()
    assert "claude-managed" in r.output and "managed-mcp.json is the enforcing file" in r.output
    # both are valid JSON
    json.loads((tmp_path / "managed-mcp.json").read_text())
    json.loads((tmp_path / "managed-settings.json").read_text())
