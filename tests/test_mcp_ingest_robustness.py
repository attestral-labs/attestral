"""MCP ingest must fail closed on valid-JSON-that-is-not-a-config.

A file matching the .mcp.json / mcp*.json / claude_desktop_config.json globs can
be valid JSON that is not an object - a top-level array or scalar. The ingester
must skip it, not crash. This is the fail-closed ingest invariant, and the
difference between a clean `scan .` and a traceback on someone's monorepo.
"""
from __future__ import annotations

from attestral.ingest import build_model


def test_top_level_array_mcp_json_is_skipped_not_crashed(tmp_path):
    (tmp_path / ".mcp.json").write_text('[{"name": "not-a-config"}]')
    model = build_model(str(tmp_path))          # must not raise
    assert not model.by_type("mcp_server")      # nothing ingested from a non-config


def test_scalar_config_is_skipped_but_a_valid_sibling_still_ingests(tmp_path):
    (tmp_path / "a.mcp.json").write_text('"just a string"')
    (tmp_path / "b.mcp.json").write_text(
        '{"mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}')
    model = build_model(str(tmp_path))          # the scalar is skipped, no crash
    assert "web" in {c.name for c in model.by_type("mcp_server")}
