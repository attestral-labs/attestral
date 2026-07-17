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


def test_known_cve_version_fires_atl117():
    # legacy-bridge launches mcp-remote@0.1.10 (CVE-2025-6514, <= 0.1.15).
    assert "ATL-117" in _ids()


def test_known_cve_version_detail_recorded():
    model = build_model(FIXTURE)
    srv = model.get("mcp_server.legacy-bridge")
    assert srv.attr("_has_known_cve") is True
    assert srv.attr("_known_cve") == "CVE-2025-6514"


def test_patched_version_not_flagged(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"ok": {"command": "npx", "args": ["mcp-remote@0.2.0", "https://x/mcp"]}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.ok").attr("_has_known_cve") is False
    assert "ATL-117" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_unpinned_version_not_cve_flagged(tmp_path):
    # mcp-remote@latest has no comparable version: ATL-106's job, not ATL-117.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"m": {"command": "npx", "args": ["mcp-remote@latest"]}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.m").attr("_has_known_cve") is False


def test_hook_config_injection_fires_atl118():
    model = build_model("examples/hook-injection")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-118" in ids
    cfg = next(c for c in model.by_type("agent_config"))
    assert cfg.attr("_hook_runs_commands") is True


def test_hookless_settings_not_flagged(tmp_path):
    d = tmp_path / ".claude"
    d.mkdir()
    (d / "settings.json").write_text('{"model": "sonnet", "permissions": {"allow": []}}')
    from attestral.ingest.agent_config import ingest_agent_config
    from attestral.model import SystemModel
    model = ingest_agent_config(tmp_path, SystemModel())
    cfg = next(iter(model.by_type("agent_config")), None)
    assert cfg is not None and cfg.attr("_hook_runs_commands") is False
    assert "ATL-118" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_skill_broad_tools_fires_atl116():
    # deploy-helper SKILL.md grants allowed-tools including Bash.
    assert "ATL-116" in _ids()


def test_skill_ingested_as_agent_instruction():
    model = build_model(FIXTURE)
    skills = [c for c in model.by_type("agent_instruction") if c.attr("_is_skill")]
    assert skills and skills[0].name == "deploy-helper"
    assert skills[0].attr("_skill_broad_tools") is True


def test_readonly_skill_does_not_fire(tmp_path):
    d = tmp_path / "skills" / "reader"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: reader\ndescription: read docs\nallowed-tools: Read, Grep\n---\nRead only.\n"
    )
    model = build_model(str(tmp_path))
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-116" not in ids


def test_skill_without_tool_grant_is_not_flagged(tmp_path):
    d = tmp_path / "skills" / "vague"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("---\nname: vague\ndescription: x\n---\nNo tools declared.\n")
    model = build_model(str(tmp_path))
    skill = model.get("agent_instruction.vague")
    assert skill is not None and skill.attr("_skill_broad_tools") is None
    assert "ATL-116" not in {f.rule_id for f in RuleEngine().evaluate(model)}


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


def test_agentcore_full_access_policy_fires_atl144():
    # Bedrock AgentCore runtime role attached to BedrockAgentCoreFullAccess.
    model = build_model("examples/agentcore-iam")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-144" in ids


def test_scoped_agentcore_policy_not_flagged(tmp_path):
    (tmp_path / "main.tf").write_text(
        'resource "aws_iam_role_policy_attachment" "scoped" {\n'
        '  role       = "agentcore-runtime-role"\n'
        '  policy_arn = "arn:aws:iam::123456789012:policy/agentcore-scoped-policy"\n'
        "}\n"
    )
    model = build_model(str(tmp_path))
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-144" not in ids


def test_known_cve_actors_mcp_server_fires_atl117(tmp_path):
    # CVE-2026-50143: @apify/actors-mcp-server <= 0.10.10, URL-authority
    # injection leaking the Apify bearer token to an attacker host.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"apify": {"command": "npx", '
        '"args": ["@apify/actors-mcp-server@0.10.10"]}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    srv = model.get("mcp_server.apify")
    assert srv.attr("_has_known_cve") is True
    assert srv.attr("_known_cve") == "CVE-2026-50143"
    assert "ATL-117" in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_patched_actors_mcp_server_not_flagged(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"apify": {"command": "npx", '
        '"args": ["@apify/actors-mcp-server@0.10.11"]}}}'
    )
    from attestral.ingest.mcp import ingest_mcp
    from attestral.model import SystemModel
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.apify").attr("_has_known_cve") is False
