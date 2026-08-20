"""FastMCP / mcp-SDK server IMPLEMENTATIONS are ingested and reviewed.

Attestral reviews not only client `.mcp.json` configs but MCP server
implementations written against the `mcp` / FastMCP SDK - a Python server that
decorates tools with `@server.tool()`. This capability was validated in the wild
against Damn Vulnerable MCP (2026-08-19); this locks it in as a committed
regression so the recognition can't silently break.
"""
from __future__ import annotations

from attestral.ingest import build_model
from attestral.rules import RuleEngine


def test_fastmcp_server_is_ingested_as_a_code_agent():
    model = build_model("examples/fastmcp-trifecta")
    agents = list(model.by_type("code_agent"))
    assert len(agents) == 1  # the server implementation itself is a reviewed surface
    caps = set(agents[0].attr("_capabilities") or [])
    assert {"network", "shell"} <= caps  # the trifecta legs are read from its @server.tool()s


def test_fastmcp_trifecta_fires():
    model = build_model("examples/fastmcp-trifecta")
    ids = {f.rule_id for f in RuleEngine().evaluate(model)}
    assert "ATL-202" in ids  # lethal trifecta across the server's own tools
    assert "ATL-207" in ids  # untrusted input reaches a sink
