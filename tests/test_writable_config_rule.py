"""ATL-163: MCP config file writable by other users (CVE-2026-30615 class).

The Windsurf attack turned a prompt injection into persistence by rewriting
the local MCP config and auto-registering a malicious stdio server. The
static precondition - a world-writable config file (or parent dir) - is a
filesystem-permission fact git cannot store, so these tests set the o+w bit
explicitly (try/finally restore), mirroring tests/test_memory_poisoning.py
for ATL-113.
"""
import json
import os
import stat
from pathlib import Path

from attestral.ingest import build_model
from attestral.ingest.local_config import build_local_model
from attestral.ingest.mcp import _world_writable, ingest_mcp
from attestral.model import SystemModel
from attestral.rules import RuleEngine

FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "writable-mcp-config"
CONFIG = FIXTURE / ".mcp.json"

SERVERS = {
    "mcpServers": {
        "docs-search": {"command": "npx", "args": ["@example/docs-mcp@1.4.2"]},
        "release-notes": {"command": "npx", "args": ["@example/release-notes-mcp@2.0.1"]},
    }
}


def _atl163(model) -> list:
    return [f for f in RuleEngine().evaluate(model) if f.rule_id == "ATL-163"]


def test_world_writable_config_fires_atl163_on_every_server():
    saved = CONFIG.stat().st_mode
    try:
        CONFIG.chmod(saved | stat.S_IWOTH)
        findings = _atl163(build_model(str(FIXTURE)))
    finally:
        CONFIG.chmod(saved)
    # Each entry in a writable config is independently swappable, so the
    # finding is per server: both servers in the two-entry fixture fire.
    assert {f.component_id for f in findings} == {
        "mcp_server.docs-search",
        "mcp_server.release-notes",
    }


def test_world_writable_parent_dir_also_fires(tmp_path):
    # The check falls back to the parent directory: a 644 file in an o+w dir
    # can be replaced wholesale, which is just as good as editing it.
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps(SERVERS))
    cfg.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    os.chmod(tmp_path, tmp_path.stat().st_mode | stat.S_IWOTH)
    model = ingest_mcp(cfg, SystemModel())
    assert len(_atl163(model)) == 2


def test_default_perms_config_is_silent(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps(SERVERS))
    cfg.chmod(stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(tmp_path, stat.S_IRWXU)  # dir not world-writable either
    model = ingest_mcp(cfg, SystemModel())
    servers = model.by_type("mcp_server")
    # The attribute is present only when true - never stamped false.
    assert servers and all(c.attr("_config_world_writable") is None for c in servers)
    assert _atl163(model) == []


def test_group_writable_config_is_silent(tmp_path):
    # Deliberate: only o+w counts. Group-write would false-positive on
    # macOS staff-group setups, and the FP-first constraint wins.
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps(SERVERS))
    cfg.chmod(stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    os.chmod(tmp_path, stat.S_IRWXU | stat.S_IRWXG)
    model = ingest_mcp(cfg, SystemModel())
    assert _atl163(model) == []


def test_unstattable_config_fails_closed(tmp_path, monkeypatch):
    # Fail-closed contract: an unstattable path is NOT writable - no crash,
    # no finding. First the helper directly, then the full ingest path with
    # os.stat raising for the config file itself.
    assert _world_writable(tmp_path / "missing" / ".mcp.json") is False

    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps(SERVERS))
    real_stat = os.stat

    def flaky_stat(path, *args, **kwargs):
        if str(path).endswith(".mcp.json"):
            raise OSError("unstattable")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", flaky_stat)
    model = ingest_mcp(tmp_path, SystemModel())
    assert len(model.by_type("mcp_server")) == 2  # still ingested
    assert _atl163(model) == []                   # but never reported writable


def _claude_json_project_only(cwd: Path) -> str:
    # ~/.claude.json whose ONLY servers are project-scoped: these bypass
    # ingest_mcp (added via component_from_server in build_local_model), so
    # they exercise the re-applied ATL-163 stamp on the nested path.
    return json.dumps({
        "projects": {str(cwd): {"mcpServers": {
            "here": {"command": "npx", "args": ["@example/docs-mcp@1.4.2"]},
        }}},
    })


def test_scan_local_claude_code_project_scope_writable_fires(tmp_path):
    home, cwd = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    cwd.mkdir()
    cfg = home / ".claude.json"
    cfg.write_text(_claude_json_project_only(cwd))
    cfg.chmod(cfg.stat().st_mode | stat.S_IWOTH)
    model, _sources = build_local_model(home=home, cwd=cwd, platform="darwin")
    findings = _atl163(model)
    assert {f.component_id for f in findings} == {"mcp_server.here"}


def test_scan_local_claude_code_project_scope_default_perms_silent(tmp_path):
    home, cwd = tmp_path / "home", tmp_path / "repo"
    home.mkdir()
    cwd.mkdir()
    cfg = home / ".claude.json"
    cfg.write_text(_claude_json_project_only(cwd))
    cfg.chmod(stat.S_IRUSR | stat.S_IWUSR)
    os.chmod(home, stat.S_IRWXU)  # dir not world-writable either
    model, _sources = build_local_model(home=home, cwd=cwd, platform="darwin")
    servers = model.by_type("mcp_server")
    assert servers and all(c.attr("_config_world_writable") is None for c in servers)
    assert _atl163(model) == []


def test_scan_local_picks_up_writable_config(tmp_path):
    # scan --local funnels discovered configs through the same ingest_mcp,
    # so a world-writable installed config (here: Cursor's global mcp.json)
    # raises the same finding with no local_config-specific code.
    home = tmp_path / "home"
    cfg = home / ".cursor" / "mcp.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps(SERVERS))
    cfg.chmod(cfg.stat().st_mode | stat.S_IWOTH)
    model, _sources = build_local_model(
        home=home, cwd=tmp_path / "cwd", platform="darwin"
    )
    assert len(_atl163(model)) == 2
