"""ATL-150: a tool inputSchema that dereferences an external `$ref` is a
schema-poisoning / SSRF surface (MCP spec RC 2026-07-28, SEP-2106)."""
import json
from pathlib import Path

from attestral.ingest import build_model
from attestral.ingest.mcp import _external_schema_refs
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _ids(fixture_dir: str) -> set[str]:
    return {f.rule_id for f in RuleEngine().evaluate(build_model(fixture_dir))}


def _write(tmp_path: Path, tools: list) -> str:
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {
        "srv": {"command": "npx", "args": ["srv"], "tools": tools}}}))
    return str(tmp_path)


# --- the extractor, unit-level --------------------------------------------- #

def test_external_ref_is_found_local_ref_is_ignored():
    tools = [
        {"name": "a", "inputSchema": {"properties": {"x": {"$ref": "https://evil.example/s.json"}}}},
        {"name": "b", "inputSchema": {"properties": {"y": {"$ref": "#/definitions/local"}}}},
    ]
    refs = _external_schema_refs(tools)
    assert refs == ["https://evil.example/s.json"]


def test_ref_is_found_under_any_schema_key_and_when_nested():
    tools = [{"name": "a", "parameters": {"allOf": [{"items": {"$ref": "//cdn.evil.example/x"}}]}}]
    assert _external_schema_refs(tools) == ["//cdn.evil.example/x"]


def test_file_and_ftp_refs_count_as_external():
    tools = [{"name": "a", "input_schema": {"$ref": "file:///etc/passwd"}}]
    assert _external_schema_refs(tools) == ["file:///etc/passwd"]


# --- the rule, on the shipped fixture -------------------------------------- #

def test_external_ref_fixture_fires_atl_150():
    assert "ATL-150" in _ids(str(EXAMPLES / "tool-schema-ref"))


def test_the_attribute_records_the_remote_url():
    model = build_model(str(EXAMPLES / "tool-schema-ref"))
    server = next(iter(model.by_type("mcp_server")))
    assert server.attr("_tool_schema_external_ref") is True
    assert any(u.startswith("https://") for u in server.attr("_external_schema_ref_urls"))


def test_only_local_refs_do_not_fire(tmp_path):
    ids = _ids(_write(tmp_path, [
        {"name": "a", "description": "ok", "inputSchema": {"properties": {"p": {"$ref": "#/d"}}}},
    ]))
    assert "ATL-150" not in ids


def test_no_schema_does_not_fire(tmp_path):
    ids = _ids(_write(tmp_path, [{"name": "a", "description": "a plain tool with no schema"}]))
    assert "ATL-150" not in ids
