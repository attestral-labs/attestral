"""ATL-102 precision: an over-broad filesystem/exec root fires, a correctly
scoped project subdirectory does not.

ATL-102 used to match any launch arg under `/`, `~`, `/home`, or `/Users`, which
false-positived on every developer who pointed a filesystem server at their own
repo (which lives under `/Users/<them>` or `/home/<them>`). The ingester now
classifies the broadest grant as root / system / home / project, and only the
first three fire, so scoping a server to a real working directory is clean.
"""
from attestral.ingest import build_model
from attestral.ingest.mcp import _broadest_fs_scope, _classify_path_scope, ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = "examples/overbroad-fs-root"


def test_fixture_fires_on_home_grant_not_project_subdir():
    model = build_model(FIXTURE)
    hits = [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-102"]
    assert {f.component_id for f in hits} == {"mcp_server.home-files"}
    scopes = {c.name: c.attr("_fs_root_scope") for c in model.by_type("mcp_server")}
    assert scopes == {"home-files": "home", "project-files": None}


def test_scope_classification():
    assert _classify_path_scope("/") == "root"
    assert _classify_path_scope("C:\\") == "root"
    assert _classify_path_scope("//") == "root"
    assert _classify_path_scope("/etc") == "system"
    assert _classify_path_scope("/etc/ssl") == "system"
    assert _classify_path_scope("C:\\Windows") == "system"
    assert _classify_path_scope("/Users/alice") == "home"
    assert _classify_path_scope("/home/bob") == "home"
    assert _classify_path_scope("~") == "home"
    assert _classify_path_scope("$HOME") == "home"
    # Safe: a specific subdirectory, even under home, is "project".
    assert _classify_path_scope("/Users/alice/code/app") == "project"
    assert _classify_path_scope("~/repo") == "project"
    assert _classify_path_scope("/srv/data") == "project"
    # Not a path at all (package names, flags).
    assert _classify_path_scope("@modelcontextprotocol/server-filesystem") is None
    assert _classify_path_scope("server-filesystem") is None
    assert _classify_path_scope("-y") is None


def test_broadest_scope_wins_and_flag_glued_paths_are_read():
    assert _broadest_fs_scope(["-y", "server-filesystem", "/srv/app", "/"]) == "root"
    assert _broadest_fs_scope(["--allowed-dir=/etc", "/srv/app"]) == "system"
    assert _broadest_fs_scope(["/srv/app", "/srv/data"]) == "project"
    assert _broadest_fs_scope(["-y", "server-fetch"]) is None


def test_network_only_server_with_a_path_arg_is_not_flagged(tmp_path):
    # Fail-closed: the scope is only derived for disk-capable servers, so a
    # network server that happens to take a path never fires ATL-102.
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"web": {"command": "npx", '
        '"args": ["@modelcontextprotocol/server-puppeteer", "/"]}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.web").attr("_fs_root_scope") is None
    assert "ATL-102" not in {f.rule_id for f in RuleEngine().evaluate(model)}


def test_shell_server_rooted_at_system_dir_fires(tmp_path):
    cfg = tmp_path / "mcp.json"
    cfg.write_text(
        '{"mcpServers": {"ops": {"command": "bash", '
        '"args": ["-c", "exec mcp-shell-server", "/root"]}}}'
    )
    model = ingest_mcp(cfg, SystemModel())
    assert model.get("mcp_server.ops").attr("_fs_root_scope") == "system"
    assert "ATL-102" in {f.rule_id for f in RuleEngine().evaluate(model)}
