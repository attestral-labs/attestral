"""ATL-158: a tool inputSchema property carrying the `x-mcp-header` mapping
key (MCP SEP-2243) - model-controlled argument values mirrored into transport
HTTP headers that intermediaries route and enforce policy on. An ordinary
schema, or a malformed (non-string) mapping, must never fire."""
import json
from pathlib import Path

from attestral.ingest import build_model
from attestral.ingest.mcp import _header_mapped_params
from attestral.rules import RuleEngine
from _helpers import ids_for

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _ids(root: str) -> set[str]:
    return {f.rule_id for f in RuleEngine().evaluate(build_model(root))}


def _server(tmp_path: Path, tools) -> str:
    (tmp_path / "mcp.json").write_text(json.dumps({
        "mcpServers": {"s": {"url": "https://mcp.example.com/mcp", "tools": tools}}
    }))
    return str(tmp_path)


def test_fixture_fires_atl158():
    assert "ATL-158" in ids_for(EXAMPLES / "header-mapped-params")


def test_mapped_params_are_surfaced_on_the_component():
    model = build_model(str(EXAMPLES / "header-mapped-params"))
    srv = model.get("mcp_server.usage-metrics")
    assert srv.attr("_has_header_mapped_params") is True
    assert srv.attr("_header_mapped_params") == [
        "query_metrics.tenant_id -> Mcp-Param-TenantId"
    ]


def test_nested_property_mapping_is_seen(tmp_path):
    # SEP-2243 allows x-mcp-header at any nesting depth in the inputSchema.
    tools = [{"name": "t", "inputSchema": {"type": "object", "properties": {
        "scope": {"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"}}}}}}]
    assert "ATL-158" in _ids(_server(tmp_path, tools))


def test_plain_schema_does_not_fire(tmp_path):
    tools = [{"name": "t", "inputSchema": {"type": "object", "properties": {
        "query": {"type": "string", "description": "A search query."}}}}]
    assert "ATL-158" not in _ids(_server(tmp_path, tools))


def test_non_string_mapping_fails_closed(tmp_path):
    # The SEP requires a string header name; anything else derives nothing.
    tools = [{"name": "t", "inputSchema": {"type": "object", "properties": {
        "region": {"type": "string", "x-mcp-header": True}}}}]
    assert "ATL-158" not in _ids(_server(tmp_path, tools))


def test_walker_fails_closed_on_junk():
    assert _header_mapped_params(None) == []
    assert _header_mapped_params("tools") == []
    assert _header_mapped_params([{"name": "t"}, "junk", 3]) == []
