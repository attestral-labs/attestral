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


def test_confused_deputy_fires_atl115():
    # crm-proxy: remote url + a downstream Salesforce token in env.
    assert "ATL-115" in _ids()


def test_confused_deputy_needs_both_remote_and_cred(tmp_path):
    # Remote server with NO downstream credential must not trip ATL-115.
    cfg = tmp_path / "mcp.json"
    cfg.write_text('{"mcpServers": {"pub": {"url": "https://pub.example.com/mcp"}}}')
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    srv = model.get("mcp_server.pub")
    assert srv.attr("_confused_deputy") is False
    assert "ATL-115" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_header_authed_remote_is_not_confused_deputy(tmp_path):
    # A client auth header is inbound auth TO the endpoint (ATL-109's fix),
    # NOT a downstream credential - it must not trip ATL-115.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"github-remote": {"url": "https://api.githubcopilot.com/mcp/",'
        ' "headers": {"Authorization": "Bearer ghp_clientToken"}}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    srv = model.get("mcp_server.github-remote")
    assert srv.attr("_confused_deputy") is False
    assert srv.attr("_remote_unauthed") is False  # it IS authenticated
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-115" not in ids and "ATL-109" not in ids


def test_malformed_taint_flow_noniterable_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: X-3\n    title: bad\n    severity: high\n    target: model\n"
        "    match: { model_taint_flow: { sources: 5, sinks: 5 } }\n"
    )
    model = build_model(FIXTURE)  # must not raise
    assert "X-3" not in {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}


def test_local_server_with_secret_is_not_confused_deputy(tmp_path):
    # A stdio server (no url) holding a secret is ATL-104's job, not a deputy.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"local": {"command": "npx", "args": ["x"],'
        ' "env": {"API_TOKEN": "s"}}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.local").attr("_confused_deputy") is None
    assert "ATL-115" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_taint_flow_fires_atl207():
    # web (network source) + ops (shell sink) share the fleet -> unsafe flow.
    assert "ATL-207" in _ids()


def test_taint_edges_recorded_in_model():
    model = build_model(FIXTURE)
    kinds = {e.kind for e in model.edges}
    assert "taint_source" in kinds and "taint_sink" in kinds


def test_taint_flow_needs_both_sides(tmp_path):
    # A lone shell server (sink, no untrusted-input source) must not trip ATL-207.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"ops": {"command": "bash", "args": ["-c", "mcp-shell"]}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    assert "ATL-207" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_malformed_taint_flow_fails_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n  - id: X-2\n    title: bad\n    severity: high\n    target: model\n"
        "    match: { model_taint_flow: { sources: [] } }\n"
    )
    model = build_model(FIXTURE)
    assert "X-2" not in {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}


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
