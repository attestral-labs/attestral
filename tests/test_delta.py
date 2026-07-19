"""Security-impact delta between two design revisions (issue #80)."""
from pathlib import Path

from click.testing import CliRunner

from attestral.cli import main
from attestral.delta import diff_models, render_delta_markdown
from attestral.ingest import build_model
from attestral.model import Severity

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BASE = str(EXAMPLES / "delta-base")
HEAD = str(EXAMPLES / "delta-head")


def test_adding_the_shell_server_is_a_regression():
    d = diff_models(build_model(BASE), build_model(HEAD))
    assert not d.is_empty
    assert d.has_regression
    # the one new server, and the capability it brought.
    added = {c.name: c for c in d.added}
    assert "runner" in added and "shell" in added["runner"].caps_gained
    # the pivot it supplied opens a reachable path and lights the trifecta.
    assert d.new_paths
    assert d.worst_new_severity() == Severity.CRITICAL
    assert any(f.rule_id == "ATL-103" for f in d.new_findings)
    # worst-case reach rises.
    assert d.blast_after > d.blast_before


def test_removing_it_is_an_improvement_not_a_regression():
    d = diff_models(build_model(HEAD), build_model(BASE))
    assert not d.has_regression
    assert d.closed_paths and d.resolved_findings
    assert any(c.name == "runner" for c in d.removed)


def test_identical_revisions_report_no_change():
    d = diff_models(build_model(BASE), build_model(BASE))
    assert d.is_empty
    assert "No change" in render_delta_markdown(d)


def test_markdown_leads_with_regressions_and_carries_the_caveat():
    md = render_delta_markdown(diff_models(build_model(BASE), build_model(HEAD)))
    assert "New reachable attack path" in md
    assert "runner" in md and "ATL-103" in md
    assert "necessary, not sufficient" in md
    # regressions come before any improvements block.
    assert md.index("New reachable attack path") < md.index("blast radius") \
        if "blast radius" in md else True


def test_cli_gate_fails_only_when_a_new_finding_crosses_the_floor():
    runner = CliRunner()
    hot = runner.invoke(main, ["diff", BASE, HEAD, "--fail-on", "high"])
    assert hot.exit_code == 1 and "introduces a new" in hot.output

    clean = runner.invoke(main, ["diff", BASE, BASE, "--fail-on", "critical"])
    assert clean.exit_code == 0

    no_gate = runner.invoke(main, ["diff", BASE, HEAD])
    assert no_gate.exit_code == 0 and "security-impact delta" in no_gate.output
