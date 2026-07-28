"""M7: the compact PR / job-summary markdown, and the md-summary scan format."""
from click.testing import CliRunner

from attestral.cli import main
from attestral.evidence import render_pr_summary
from attestral.ingest import build_model
from attestral.model import Component, Finding, Severity, SystemModel
from attestral.reachability import annotate_reachability
from attestral.rules import RuleEngine


def _model_findings(fixture: str):
    model = build_model(fixture)
    findings = RuleEngine().evaluate(model)
    annotate_reachability(model, findings)
    return model, findings


def test_summary_renders_paths_and_reachability_column():
    model, findings = _model_findings("examples/vulnerable-agent")
    md = render_pr_summary(model, findings, "demo")
    assert md.startswith("## Attestral design review")
    assert "### Reachable attack paths (1)" in md
    assert "internal chain" in md
    assert "| Severity | Finding | Component | Reachability |" in md
    assert "Shell-capable MCP server" in md  # the title lands in the table
    # a raised finding names the chain and the escalation in its row
    assert "on internal chain (entry+impact), raised from medium" in md


def test_summary_net_new_wording_and_singular():
    model = build_model("examples/vulnerable-agent")
    one = [Finding("ATL-103", "shell", Severity.CRITICAL, "mcp_server.shell", "d", "r")]
    md = render_pr_summary(model, one, "demo", net_new=True)
    assert "1** net-new finding introduced by this change" in md  # singular
    assert "findings introduced" not in md


def test_summary_clean_scan():
    # A substantial, finding-free surface is a genuine clean scan.
    model = SystemModel()
    for i in range(2):
        model.add(Component(id=f"s{i}", type="mcp_server", name=f"s{i}", source=f"s{i}.json"))
    assert "Clean scan." in render_pr_summary(model, [], "t")
    # A baseline-gated run reports only the delta, so no scope caveat applies.
    assert "No new findings." in render_pr_summary(SystemModel(), [], "t", net_new=True)


def test_summary_empty_scope_is_not_a_clean_bill():
    # An empty model reviewed nothing; it must not read as "Clean scan."
    md = render_pr_summary(SystemModel(), [], "t")
    assert "Clean scan." not in md
    assert "not a clean bill of health" in md


def test_summary_thin_surface_is_caveated():
    # A single agent/MCP surface is too little for the composition checks to fire.
    model = SystemModel()
    model.add(Component(id="only", type="mcp_server", name="only", source="only.json"))
    md = render_pr_summary(model, [], "t")
    assert "Clean scan." not in md
    assert "at least two connected surfaces" in md


def test_summary_escapes_pipes_in_titles():
    f = [Finding("ATL-X", "a | b title", Severity.LOW, "c", "d", "r")]
    md = render_pr_summary(SystemModel(), f, "t")
    assert "ATL-X" in md  # rendered without breaking the table


def test_md_summary_format_writes_file(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]},'
        ' "ops": {"command": "bash", "args": ["-c", "x"]}}}'
    )
    runner = CliRunner()
    out = tmp_path / "rep"
    r = runner.invoke(main, ["scan", str(tmp_path), "--format", "md-summary", "-o", str(out)])
    assert r.exit_code == 0, r.output
    summary = tmp_path / "rep.summary.md"
    assert summary.exists()
    assert "Reachable attack paths" in summary.read_text()


def test_md_summary_reflects_net_new_under_baseline(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}'
    )
    runner = CliRunner()
    bl = tmp_path / "bl.json"
    runner.invoke(main, ["scan", str(tmp_path), "--baseline", str(bl)])  # record
    # add a server that introduces new findings
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]},'
        ' "ops": {"command": "bash", "args": ["-c", "x"]}}}'
    )
    out = tmp_path / "rep"
    runner.invoke(main, ["scan", str(tmp_path), "--baseline", str(bl),
                         "--format", "md-summary", "-o", str(out)])
    assert "net-new" in (tmp_path / "rep.summary.md").read_text()
