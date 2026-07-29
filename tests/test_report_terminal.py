"""Terminal report rendering: fleet inventory and summary grammar."""
import json

from attestral.ingest.local_config import build_local_model
from attestral.model import Component, Finding, Severity, SystemModel
from attestral.report_terminal import (
    clean_scan_category,
    render_card,
    render_fleet,
    render_scan,
)


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


def _trifecta(cid="model"):
    return Finding("ATL-202", "Tool fleet forms an exfiltration chain (lethal trifecta)",
                   Severity.CRITICAL, cid, "d", "fix")


def test_card_headlines_the_trifecta_and_carries_the_cta():
    model = _servers(3)
    card = render_card(model, [_trifecta()], "on this machine", color=False)
    assert "LETHAL TRIFECTA" in card
    assert "3 MCP/agent surfaces reviewed on this machine" in card
    assert "1 critical" in card
    assert "attestral scan --local" in card                 # the shareable CTA
    assert "research.html" in card                          # drives to the study


def test_card_is_honest_on_a_thin_surface_not_a_scare():
    model = _servers(1)
    card = render_card(model, [], "on this machine", color=False)
    assert "LETHAL TRIFECTA" not in card
    assert "thin result, not a clean bill of health" in card


def test_card_gives_a_clean_machine_a_satisfying_result():
    model = _servers(2)
    card = render_card(model, [], "on this machine", color=False)
    assert "No lethal trifecta, no toxic flow. Clean." in card


def test_card_says_nothing_in_scope_when_empty():
    card = render_card(SystemModel(), [], "on this machine", color=False)
    assert "No agent or MCP surface found" in card
    assert "LETHAL TRIFECTA" not in card


def test_card_cli_flag_replaces_the_full_report(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]},'
        ' "ops": {"command": "bash", "args": ["-c", "x"]}}}'
    )
    from click.testing import CliRunner

    from attestral.cli import main
    r = CliRunner().invoke(main, ["scan", str(tmp_path), "--card"])
    assert r.exit_code == 0, r.output
    assert "agentic self-audit" in r.output
    assert "no files written" not in r.output              # card is a clean artifact
