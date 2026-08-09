"""`attestral compile --target copilot-registry` - the attested design as a
GitHub Copilot internal MCP registry v0.1 catalog.

Proves the emitted catalog is a valid `GET /v0.1/servers` list response of only
the attested-allowed servers: each entry is a wrapped server.json with a
reverse-DNS name, a remotes[] (for a hosted server) or packages[] (for a stdio
launch), and the registry-managed _meta block, deterministic (no timestamps).
"""
import json

from click.testing import CliRunner

from attestral.cli import main
from attestral.compile import compile_copilot_registry, compile_policy
from attestral.ingest import build_model
from attestral.model import Component, SystemModel
from attestral.rules.engine import RuleEngine

FIXTURE = "examples/guard-runtime"


def _catalog(fixture=FIXTURE):
    model = build_model(fixture)
    policy = compile_policy(model, RuleEngine().evaluate(model))
    return json.loads(compile_copilot_registry(model, policy))


# -- envelope + default-deny --

def test_catalog_is_v01_list_envelope_of_allowed_only():
    cat = _catalog()
    assert set(cat) == {"servers", "metadata"}
    assert cat["metadata"]["count"] == len(cat["servers"]) == 1  # docs only
    names = [e["server"]["name"] for e in cat["servers"]]
    assert all("root-files" not in n for n in names)  # denied absent
    # each element is wrapped: {server, _meta}, never a bare server.json
    for e in cat["servers"]:
        assert set(e) >= {"server", "_meta"}


# -- a stdio server resolves to an installable packages[] entry --

def test_stdio_server_becomes_npm_package_entry():
    server = _catalog()["servers"][0]["server"]
    assert server["$schema"].endswith("server.schema.json")
    assert "/" in server["name"] and "." in server["name"].split("/")[0]  # reverse-DNS
    pkg = server["packages"][0]
    assert pkg["registryType"] == "npm"
    assert pkg["identifier"] == "@modelcontextprotocol/server-filesystem"
    assert pkg["version"] == "2025.7.1"
    assert pkg["transport"] == {"type": "stdio"}
    assert "remotes" not in server


def test_meta_is_canonical_and_deterministic():
    meta = _catalog()["servers"][0]["_meta"]["io.modelcontextprotocol.registry/official"]
    assert meta == {"status": "active", "isLatest": True}  # no non-deterministic timestamps


# -- a hosted (url) server becomes a remotes[] entry --

def _model_policy(component, allow=True):
    model = SystemModel()
    model.add(component)
    return model, {"servers": {component.name: {"allow": allow}}}


def test_hosted_server_becomes_streamable_http_remote():
    c = Component(id="mcp_server.api", type="mcp_server", name="api", source="cfg",
                  attributes={"url": "https://mcp.example.com/mcp"},
                  trust_boundary="agent_runtime")
    model, policy = _model_policy(c)
    server = json.loads(compile_copilot_registry(model, policy))["servers"][0]["server"]
    assert server["remotes"] == [{"type": "streamable-http",
                                  "url": "https://mcp.example.com/mcp"}]
    assert "packages" not in server


def test_reverse_dns_name_is_passed_through():
    c = Component(id="mcp_server.x", type="mcp_server", name="io.github.acme/widget",
                  source="cfg", attributes={"url": "https://w.example/mcp"},
                  trust_boundary="agent_runtime")
    model, policy = _model_policy(c)
    server = json.loads(compile_copilot_registry(model, policy))["servers"][0]["server"]
    assert server["name"] == "io.github.acme/widget"  # not re-namespaced


def test_long_description_truncated_to_100():
    c = Component(id="mcp_server.x", type="mcp_server", name="x", source="cfg",
                  attributes={"url": "https://x.example/mcp", "description": "z" * 250},
                  trust_boundary="agent_runtime")
    model, policy = _model_policy(c)
    server = json.loads(compile_copilot_registry(model, policy))["servers"][0]["server"]
    assert len(server["description"]) == 100


def test_denied_server_omitted_from_catalog():
    c = Component(id="mcp_server.api", type="mcp_server", name="api", source="cfg",
                  attributes={"url": "https://mcp.example.com/mcp"},
                  trust_boundary="agent_runtime")
    model, policy = _model_policy(c, allow=False)
    cat = json.loads(compile_copilot_registry(model, policy))
    assert cat["servers"] == [] and cat["metadata"]["count"] == 0


# -- CLI writes a valid catalog + serving guidance --

def test_cli_writes_catalog(tmp_path):
    out = tmp_path / "registry.json"
    r = CliRunner().invoke(main, ["compile", FIXTURE, "--target", "copilot-registry",
                                  "-o", str(out)])
    assert r.exit_code == 0, r.output
    assert "Registry only" in r.output and "/v0.1/servers" in r.output
    cat = json.loads(out.read_text())  # valid JSON
    assert cat["metadata"]["count"] == 1
