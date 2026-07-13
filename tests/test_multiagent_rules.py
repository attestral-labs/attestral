"""Multi-agent delegation: subagent definitions, A2A cards, capability closure.

The fixture's MCP fleet is a single scoped filesystem server - safe on its
own. Every fleet-level finding exists only because subagent tool grants
compose with it across the delegation hop.
"""
from attestral.ingest import build_model
from attestral.ingest.agent_config import ingest_agent_config
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/multi-agent"


def _findings(path=FIXTURE):
    return RuleEngine().evaluate(build_model(path))


def _ids(path=FIXTURE):
    return {f.rule_id for f in _findings(path)}


def test_multiagent_wave_fires():
    assert {"ATL-119", "ATL-120", "ATL-121", "ATL-122"} <= _ids()


def test_fleet_rules_fire_through_delegation():
    # notes (filesystem) + deploy-bot (shell, network): both trifectas and the
    # taint path complete only across the delegation hop.
    assert {"ATL-202", "ATL-203", "ATL-207"} <= _ids()


def test_combo_finding_names_the_delegation_chain():
    (f,) = [f for f in _findings() if f.rule_id == "ATL-202"]
    assert "notes" in f.description and "deploy-bot" in f.description


def test_subagent_capabilities_derived_from_tool_grants(tmp_path):
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "ops.md").write_text(
        "---\nname: ops\ntools: Bash, WebFetch, Read\n---\nbody\n"
    )
    model = ingest_agent_config(tmp_path, SystemModel())
    (agent,) = model.by_type("subagent")
    assert agent.attr("_capabilities") == ["filesystem", "network", "shell"]
    assert agent.attr("_wildcard_tools") is False


def test_wildcard_subagent_contributes_no_capabilities(tmp_path):
    # A delegate that inherits everything is flagged (ATL-120) but its unknown
    # grants are never guessed into fleet findings.
    (tmp_path / "mcp.json").write_text(
        '{"mcpServers": {"notes": {"command": "npx",'
        ' "args": ["@modelcontextprotocol/server-filesystem@1.4.2", "/srv/n"]}}}'
    )
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "helper.md").write_text("---\nname: helper\n---\nbody\n")
    ids = _ids(tmp_path)
    assert "ATL-120" in ids
    assert "ATL-202" not in ids and "ATL-203" not in ids


def test_read_only_subagent_is_clean(tmp_path):
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "scout.md").write_text(
        "---\nname: scout\ntools: Read, Grep, Glob\n---\nbody\n"
    )
    ids = _ids(tmp_path)
    assert "ATL-119" not in ids and "ATL-120" not in ids and "ATL-203" not in ids


def test_malformed_frontmatter_degrades_without_crashing(tmp_path):
    agents = tmp_path / ".claude" / "agents"
    agents.mkdir(parents=True)
    (agents / "broken.md").write_text(
        "---\nname: broken\ndescription: has: colons: everywhere: [unclosed\ntools: Bash\n---\nbody\n"
    )
    model = ingest_agent_config(tmp_path, SystemModel())
    (agent,) = model.by_type("subagent")
    assert agent.name == "broken"
    assert "shell" in agent.attr("_capabilities")  # line-based fallback still binds tools


def test_authenticated_https_agent_card_is_clean(tmp_path):
    wk = tmp_path / ".well-known"
    wk.mkdir()
    (wk / "agent-card.json").write_text(
        '{"name": "triage", "url": "https://agents.example/a2a",'
        ' "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},'
        ' "security": [{"bearer": []}]}'
    )
    ids = _ids(tmp_path)
    assert "ATL-121" not in ids and "ATL-122" not in ids
