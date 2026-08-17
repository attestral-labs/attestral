"""ATL-174: MCP server auto-launched from a repo-committed IDE workspace-trust config.

Positive: a `.cursor/mcp.json` committed in a repo with a stdio launch fires.
Negatives (fail-closed): a user-global copy of the same file, a repo-root
`.mcp.json`, and a remote-`url`-only entry all stay silent.
"""
from attestral.ingest.mcp import component_from_server, ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine
from _helpers import ids_for

FIXTURE = "examples/workspace-autoload"


def _fires(comp) -> bool:
    m = SystemModel()
    m.add(comp)
    return "ATL-174" in {f.rule_id for f in RuleEngine().evaluate(m)}


def test_workspace_autoload_fires_on_fixture():
    assert "ATL-174" in ids_for(FIXTURE)


def test_workspace_autoload_attr_derived():
    from attestral.ingest import build_model
    srv = build_model(FIXTURE).get("mcp_server.repo-indexer")
    assert srv is not None
    assert srv.attr("_workspace_autoload") is True


def test_cursor_stdio_launch_fires():
    cfg = {"command": "node", "args": ["./.cursor/tools/x.js"]}
    comp = component_from_server("x", cfg, "/repo/proj/.cursor/mcp.json")
    assert comp.attr("_workspace_autoload") is True
    assert _fires(comp)


def test_amazonq_and_vscode_dirs_fire():
    for src in ("/repo/proj/.amazonq/mcp.json",
                "/repo/proj/.vscode/mcp.json",
                "/repo/proj/.claude/mcp.json"):
        comp = component_from_server("x", {"command": "node", "args": ["s.js"]}, src)
        assert comp.attr("_workspace_autoload") is True, src


def test_user_global_cursor_does_not_fire():
    # ~/.cursor/mcp.json is the developer's own install, not a repo-planted config.
    for src in ("/Users/alice/.cursor/mcp.json",
                "/home/alice/.cursor/mcp.json",
                "~/.cursor/mcp.json",
                "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json"):
        comp = component_from_server("x", {"command": "node", "args": ["s.js"]}, src)
        assert comp.attr("_workspace_autoload") is None, src
        assert not _fires(comp)


def test_repo_root_dotmcp_does_not_fire():
    # A repo-root .mcp.json is the shared team convention (approval checkpoint on
    # open); firing on it would nag every well-scoped shared config.
    comp = component_from_server("x", {"command": "node", "args": ["s.js"]},
                                 "/repo/proj/.mcp.json")
    assert comp.attr("_workspace_autoload") is None
    assert not _fires(comp)


def test_remote_url_only_does_not_fire():
    # No local launch -> nothing is auto-run on trust, even in a .cursor config.
    comp = component_from_server(
        "x", {"url": "https://api.example.com/mcp"}, "/repo/proj/.cursor/mcp.json")
    assert comp.attr("_workspace_autoload") is None
    assert not _fires(comp)


def test_missing_source_fails_closed():
    # An unstattable / empty source derives nothing (fail closed).
    comp = component_from_server("x", {"command": "node", "args": ["s.js"]}, "")
    assert comp.attr("_workspace_autoload") is None


def test_ingest_mcp_on_cursor_config(tmp_path):
    d = tmp_path / "myrepo" / ".cursor"
    d.mkdir(parents=True)
    (d / "mcp.json").write_text(
        '{"mcpServers": {"idx": {"command": "node", "args": ["./x.js"]}}}')
    model = ingest_mcp(tmp_path, SystemModel())
    srv = model.get("mcp_server.idx")
    assert srv is not None and srv.attr("_workspace_autoload") is True
