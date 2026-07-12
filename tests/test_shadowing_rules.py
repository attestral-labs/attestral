"""Coverage for the cross-server tool-shadowing wave: ATL-204/205/206."""
import json

from attestral.ingest import build_model
from attestral.ingest.mcp import ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/tool-shadowing"


def _findings(model):
    return RuleEngine().evaluate(model)


def _model_from(tmp_path, files: dict[str, dict]) -> SystemModel:
    for name, servers in files.items():
        (tmp_path / name).write_text(json.dumps({"mcpServers": servers}))
    return ingest_mcp(tmp_path, SystemModel())


def test_shadowing_wave_fires():
    ids = {f.rule_id for f in _findings(build_model(FIXTURE))}
    assert {"ATL-204", "ATL-205", "ATL-206"} <= ids


def test_collision_finding_names_tool_and_servers():
    found = [f for f in _findings(build_model(FIXTURE)) if f.rule_id == "ATL-204"]
    assert len(found) == 1
    assert found[0].component_id == "model:tool:create_issue"
    assert "linear" in found[0].description and "notes-helper" in found[0].description


def test_steering_finding_points_at_referencing_server():
    found = [f for f in _findings(build_model(FIXTURE)) if f.rule_id == "ATL-205"]
    assert len(found) == 1
    assert found[0].component_id == "mcp_server.notes-helper"
    assert "list_issues" in found[0].description and "linear" in found[0].description


def test_name_conflict_finding_lists_both_sources():
    found = [f for f in _findings(build_model(FIXTURE)) if f.rule_id == "ATL-206"]
    assert len(found) == 1
    assert found[0].component_id == "model:server:linear"
    assert "mcp.json" in found[0].source and "claude_desktop_config.json" in found[0].source


def test_distinct_tool_names_no_collision(tmp_path):
    model = _model_from(tmp_path, {"one.mcp.json": {
        "a": {"command": "npx", "args": ["a-mcp@1.0.0"],
              "tools": [{"name": "read_notes", "description": "Read notes."}]},
        "b": {"command": "npx", "args": ["b-mcp@1.0.0"],
              "tools": [{"name": "write_notes", "description": "Write notes."}]},
    }})
    ids = {f.rule_id for f in _findings(model)}
    assert "ATL-204" not in ids and "ATL-205" not in ids


def test_one_server_declaring_a_tool_twice_is_not_a_collision(tmp_path):
    model = _model_from(tmp_path, {"one.mcp.json": {
        "a": {"command": "npx", "args": ["a-mcp@1.0.0"],
              "tools": [{"name": "read_notes", "description": "Read."},
                        {"name": "read_notes", "description": "Read again."}]},
    }})
    assert "ATL-204" not in {f.rule_id for f in _findings(model)}


def test_self_reference_is_not_steering(tmp_path):
    model = _model_from(tmp_path, {"one.mcp.json": {
        "a": {"command": "npx", "args": ["a-mcp@1.0.0"],
              "tools": [{"name": "read_notes",
                         "description": "Companion to write_notes on this server."},
                        {"name": "write_notes", "description": "Write notes."}]},
        "b": {"command": "npx", "args": ["b-mcp@1.0.0"],
              "tools": [{"name": "list_tasks", "description": "List tasks."}]},
    }})
    assert "ATL-205" not in {f.rule_id for f in _findings(model)}


def test_prose_word_tool_name_is_not_matched(tmp_path):
    # Server b owns a tool named with a plain English word; a's description
    # using that word in prose must not count as a cross-server reference.
    model = _model_from(tmp_path, {"one.mcp.json": {
        "a": {"command": "npx", "args": ["a-mcp@1.0.0"],
              "tools": [{"name": "fetch_page",
                         "description": "Search the web and fetch a page."}]},
        "b": {"command": "npx", "args": ["b-mcp@1.0.0"],
              "tools": [{"name": "search", "description": "Full-text search."}]},
    }})
    assert "ATL-205" not in {f.rule_id for f in _findings(model)}


def test_mirrored_definition_is_not_a_name_conflict(tmp_path):
    servers = {"linear": {"command": "npx", "args": ["@linear/mcp-server@1.2.3"]}}
    model = _model_from(tmp_path, {"one.mcp.json": servers, "two.mcp.json": servers})
    assert "ATL-206" not in {f.rule_id for f in _findings(model)}


def test_malformed_shadowing_specs_fail_closed(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - {id: X-1, title: bad, severity: high, target: model,\n"
        '     match: {model_tool_name_collision: "yes"}}\n'
        "  - {id: X-2, title: bad, severity: high, target: model,\n"
        "     match: {model_cross_server_tool_reference: 1}}\n"
        "  - {id: X-3, title: bad, severity: high, target: model,\n"
        "     match: {model_server_name_conflict: [true]}}\n"
    )
    model = build_model(FIXTURE)
    ids = {f.rule_id for f in RuleEngine(rule_paths=[rules]).evaluate(model)}
    assert not ({"X-1", "X-2", "X-3"} & ids)


def test_tool_names_ingested_even_without_descriptions(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {
        "a": {"command": "npx", "args": ["a-mcp@1.0.0"],
              "tools": [{"name": "bare_tool"},
                        {"name": "described_tool", "description": "Does things."}]},
    }}))
    model = ingest_mcp(cfg, SystemModel())
    (server,) = model.by_type("mcp_server")
    assert server.attr("_tool_names") == ["bare_tool", "described_tool"]
    # the ML scoring surface still only carries tools that have a description
    assert [t["name"] for t in server.attr("_tool_descriptions")] == ["described_tool"]
