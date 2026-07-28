"""Terminal report rendering: fleet inventory and summary grammar."""
import json

from attestral.ingest.local_config import build_local_model
from attestral.model import Component, SystemModel
from attestral.report_terminal import clean_scan_category, render_fleet, render_scan


def _local_model(tmp_path, servers):
    cfg = tmp_path / "home" / ".claude.json"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(json.dumps({"mcpServers": servers}))
    model, _ = build_local_model(home=tmp_path / "home", cwd=tmp_path / "cwd",
                                 platform="darwin")
    return model


def test_render_fleet_lists_every_server_with_reach_and_source(tmp_path):
    model = _local_model(tmp_path, {
        "notes": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/srv"]},
        "metrics": {"url": "https://metrics.example/mcp", "env": {"METRICS_TOKEN": "x"}},
    })
    text = render_fleet(model, color=False)
    assert "Agent tool surface (2 servers)" in text
    assert "notes" in text and "stdio" in text
    assert "metrics" in text and "remote" in text
    assert "reach: filesystem" in text          # capability classes are shown
    assert ".claude.json" in text               # so is where each server came from


def test_render_fleet_empty_model_renders_nothing():
    assert render_fleet(SystemModel(), color=False) == ""


def test_summary_grammar_singular(tmp_path):
    model = _local_model(tmp_path, {
        "notes": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/srv"]},
    })
    text = render_scan(model, [], "local", color=False)
    assert "1 component · 0 findings" in text


def _servers(n):
    m = SystemModel()
    for i in range(n):
        m.add(Component(id=f"s{i}", type="mcp_server", name=f"s{i}", source=f"s{i}.json"))
    return m


def test_clean_verdict_thin_single_surface_is_not_a_clean_bill(tmp_path):
    # The reader who runs `scan --local` with one server must not read a clean
    # result as "I am safe" when the composition checks could not even fire.
    model = _local_model(tmp_path, {
        "notes": {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", "/srv"]},
    })
    text = render_scan(model, [], "local", color=False)
    assert "Clean scan." not in text
    assert "at least two connected surfaces" in text
    assert clean_scan_category(model) == "thin"


def test_clean_verdict_empty_scope(tmp_path):
    text = render_scan(SystemModel(), [], "nothing-here", color=False)
    assert "Clean scan." not in text
    assert "not a clean bill of health" in text
    assert clean_scan_category(SystemModel()) == "empty"


def test_clean_verdict_substantial_surface_is_a_clean_scan():
    model = _servers(2)
    text = render_scan(model, [], "repo", color=False)
    assert "No findings. Clean scan." in text
    assert clean_scan_category(model) == "clean"
