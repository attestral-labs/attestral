"""Coverage for the 2026 hardening + fleet-flow wave: ATL-134..140 and 214..216."""
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

SUPPLY = "examples/mcp-supply-chain"
FLOWS = "examples/agent-fleet-flows"




def _ids_from_config(tmp_path, body):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(body)
    model = ingest_mcp(cfg, SystemModel())
    return model, {f.rule_id for f in RuleEngine().evaluate(model)}


# --- Supply-chain / transport / execution hardening (per-component) ----------

def test_supply_chain_hardening_rules_fire():
    assert {"ATL-134", "ATL-135", "ATL-136", "ATL-137", "ATL-138", "ATL-140"} <= ids_for(SUPPLY)


def test_git_install_not_flagged_for_registry_package(tmp_path):
    # A normal registry package pinned to a version must not trip ATL-134.
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"ok": {"command": "npx", "args": ["@acme/tools-mcp@1.2.3"]}}}',
    )
    assert "ATL-134" not in ids


def test_git_https_url_arg_is_not_a_git_ref(tmp_path):
    # A plain https://github.com/... argument (not a github: ref) must not fire.
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch",'
        ' "--allow", "https://github.com/acme/docs"]}}}',
    )
    assert "ATL-134" not in ids


def test_tls_rule_needs_the_disabling_env_key(tmp_path):
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"ok": {"command": "npx", "args": ["x"],'
        ' "env": {"HTTPS_PROXY": "http://proxy:8080"}}}}',
    )
    assert "ATL-136" not in ids


def test_docker_rule_ignores_a_plain_container(tmp_path):
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"box": {"command": "docker",'
        ' "args": ["run", "--rm", "acme/tool-mcp:1.0.0"]}}}',
    )
    assert "ATL-137" not in ids


def test_inspect_rule_needs_the_flag(tmp_path):
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"node": {"command": "node", "args": ["./dist/server.js"]}}}',
    )
    assert "ATL-138" not in ids


def test_ws_rule_does_not_fire_on_wss(tmp_path):
    model, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"secure": {"url": "wss://tools.acme.dev/mcp"}}}',
    )
    assert "ATL-140" not in ids


# --- Code-defined agent shell (per-component) --------------------------------

def test_code_agent_shell_fires_atl139():
    # examples/code-agent/agent.py wires a subprocess-backed run_command tool.
    assert "ATL-139" in ids_for("examples/code-agent")


def test_readonly_code_agent_not_flagged(tmp_path):
    (tmp_path / "reader.py").write_text(
        "import requests\n"
        "from langchain_core.tools import tool\n\n"
        "@tool\n"
        "def fetch(url: str) -> str:\n"
        '    """Fetch a page."""\n'
        "    return requests.get(url).text\n"
    )
    model = build_model(str(tmp_path))
    agent = next(iter(model.by_type("code_agent")), None)
    assert agent is not None and "shell" not in (agent.attr("_capabilities") or [])
    assert "ATL-139" not in {f.rule_id for f in RuleEngine().evaluate(model)}


# --- Fleet flows (model-level) -----------------------------------------------

def test_fleet_flow_rules_fire():
    assert {"ATL-214", "ATL-215", "ATL-216"} <= ids_for(FLOWS)


def test_memory_poisoning_needs_an_external_source(tmp_path):
    # A lone memory store (no web/SaaS source) must not trip ATL-214.
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"memory": {"command": "npx", "args": ["mem0-mcp-server"]}}}',
    )
    assert "ATL-214" not in ids


def test_sampling_without_autonomy_not_flagged():
    # examples/mcp-capabilities declares sampling but has no auto-approve/shell.
    assert "ATL-215" not in ids_for("examples/mcp-capabilities")


def test_injection_to_cloud_needs_an_untrusted_source(tmp_path):
    # Cloud credentials but no untrusted-input tool: ATL-216 must stay quiet.
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"cloud": {"command": "npx", "args": ["@acme/aws-mcp@1.0.0"],'
        ' "env": {"AWS_ACCESS_KEY_ID": "AKIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "x"}}}}',
    )
    assert "ATL-216" not in ids


def test_injection_to_cloud_needs_cloud_credentials(tmp_path):
    # An untrusted-input tool but no cloud-credentialed server: ATL-216 quiet.
    _, ids = _ids_from_config(
        tmp_path,
        '{"mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}',
    )
    assert "ATL-216" not in ids


# --- Fail-closed on malformed model matcher specs ----------------------------

def test_malformed_sampling_matcher_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: X-215\n    title: bad\n    severity: high\n    target: model\n"
        "    match: { model_sampling_covert_invocation: yes-please }\n"
    )
    model = build_model(FLOWS)  # must not raise
    assert "X-215" not in {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}


def test_malformed_injection_cloud_matcher_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: X-216\n    title: bad\n    severity: high\n    target: model\n"
        "    match: { model_injection_reaches_cloud: [1, 2] }\n"
    )
    model = build_model(FLOWS)  # must not raise
    assert "X-216" not in {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}
