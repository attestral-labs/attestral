"""Coverage for the agentic depth wave: ATL-108..111 and fleet-combo rules 202/203."""
from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/agentic-risks"


def _ids():
    model = build_model(FIXTURE)
    return {f.rule_id for f in RuleEngine().evaluate(model)}


def test_new_agentic_rules_fire():
    assert {"ATL-108", "ATL-109", "ATL-110", "ATL-111", "ATL-112"} <= _ids()


def test_cloud_credentials_create_reachability_edge():
    model = build_model(FIXTURE)
    edges = [e for e in model.edges if e.kind == "tool_access"]
    assert any(
        e.source_id == "mcp_server.deploy" and e.target_id == "boundary:cloud"
        for e in edges
    )


def test_memory_store_fires_atl114():
    # ATL-114: a persistent memory server is a memory-poisoning target (SoK V6).
    assert "ATL-114" in _ids()


def test_memory_capability_classified():
    model = build_model(FIXTURE)
    recall = model.get("mcp_server.recall")
    assert recall and "memory" in (recall.attr("_capabilities") or [])


def test_memory_counts_toward_trifecta(tmp_path):
    # A memory store (private data) + a fetch tool (egress) alone must trip the
    # lethal trifecta - proving memory joined the private-data capability group.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {'
        '"recall": {"command": "npx", "args": ["mem0-mcp-server"]},'
        '"web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    assert "ATL-202" in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_fleet_combo_rules_fire():
    assert {"ATL-202", "ATL-203"} <= _ids()


def test_capability_classification():
    model = ingest_mcp(f"{FIXTURE}/mcp.json", SystemModel())
    caps = {c.name: c.attr("_capabilities") for c in model.by_type("mcp_server")}
    assert "filesystem" in caps["notes"]
    assert "network" in caps["web"]
    assert "shell" in caps["ops"]
    assert caps["deploy"] == []  # no hint match: classified as nothing, not guessed


def test_combo_needs_both_sides(tmp_path):
    # A scoped filesystem server alone has no egress: the trifecta must not fire.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"notes": {"command": "npx",'
        ' "args": ["@modelcontextprotocol/server-filesystem", "/srv/notes"]}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-202" not in ids and "ATL-203" not in ids


def test_malformed_combo_spec_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - id: X-1\n"
        "    title: bad spec\n"
        "    severity: high\n"
        "    target: model\n"
        '    match: { model_capability_combo: "not-a-list" }\n'
    )
    model = build_model(FIXTURE)
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}
    assert "X-1" not in ids
