"""Design-level capability-envelope diff (`attestral design-diff`).

The verdict vocabulary (WIDENED / NARROWED / UNCHANGED / MIXED) and the gate:
any widening signal - a capability gained, a standing credential appearing,
auto-approve appearing, a component added with reach, a cross-boundary edge
opened - must fail --fail-on-widen with exit 3; narrowing-only and unchanged
designs must pass.
"""
import json
from pathlib import Path

from click.testing import CliRunner

from attestral.cli import main
from attestral.designdiff import (
    MIXED,
    NARROWED,
    UNCHANGED,
    WIDENED,
    diff_designs,
    render_design_diff,
)
from attestral.ingest import build_model
from attestral.model import Component, Edge, SystemModel
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BASE = str(EXAMPLES / "diff-base")
WIDE = str(EXAMPLES / "diff-widened")


def _comp(cid: str, ctype: str = "mcp_server", boundary: str = "agent_runtime",
          **attrs) -> Component:
    return Component(id=cid, type=ctype, name=cid.split(".")[-1], source="test",
                     attributes=attrs, trust_boundary=boundary)


def _diff(old: SystemModel, new: SystemModel):
    return diff_designs(old, new, [], [])


def _fixture_diff():
    old_model, new_model = build_model(BASE), build_model(WIDE)
    return diff_designs(old_model, new_model,
                        RuleEngine().evaluate(old_model),
                        RuleEngine().evaluate(new_model))


# ---------------------------------------------------------------- components

def test_added_component_with_reach_is_a_widening():
    old = SystemModel(components=[_comp("mcp_server.web")])
    new = SystemModel(components=[
        _comp("mcp_server.web"),
        _comp("mcp_server.runner", _capabilities=["shell"]),
    ])
    d = _diff(old, new)
    assert [c.id for c in d.components_added] == ["mcp_server.runner"]
    assert "shell" in d.components_added[0].carries
    assert d.verdict == WIDENED


def test_removed_component_with_reach_is_a_narrowing():
    old = SystemModel(components=[
        _comp("mcp_server.web"),
        _comp("mcp_server.runner", _capabilities=["shell"]),
    ])
    new = SystemModel(components=[_comp("mcp_server.web")])
    d = _diff(old, new)
    assert [c.id for c in d.components_removed] == ["mcp_server.runner"]
    assert d.verdict == NARROWED


def test_pure_docs_component_is_inventory_not_widening():
    old = SystemModel(components=[_comp("mcp_server.web")])
    new = SystemModel(components=[
        _comp("mcp_server.web"),
        _comp("prompt_file.notes", ctype="prompt_file"),
    ])
    d = _diff(old, new)
    assert [c.id for c in d.components_added] == ["prompt_file.notes"]
    assert d.components_added[0].carries == []
    assert d.verdict == UNCHANGED
    assert "Inventory (no reach change)" in render_design_diff(d)


# ------------------------------------------------------- envelope widenings

def test_capability_added_on_surviving_component_widens():
    old = SystemModel(components=[_comp("mcp_server.ops", _capabilities=[])])
    new = SystemModel(components=[_comp("mcp_server.ops", _capabilities=["shell"])])
    d = _diff(old, new)
    assert d.envelope_changes[0].widenings == ["capability added: shell"]
    assert d.verdict == WIDENED


def test_secrets_appearing_in_env_widens():
    old = SystemModel(components=[_comp("mcp_server.ops", _env_has_secrets=False)])
    new = SystemModel(components=[_comp("mcp_server.ops", _env_has_secrets=True)])
    d = _diff(old, new)
    assert "secrets now in env" in d.envelope_changes[0].widenings
    assert d.verdict == WIDENED


def test_cloud_credentials_and_auto_approve_appearing_widen():
    old = SystemModel(components=[_comp("mcp_server.ops")])
    new = SystemModel(components=[
        _comp("mcp_server.ops", _has_cloud_credentials=True, _auto_approve=True)])
    d = _diff(old, new)
    assert "cloud credentials now in env" in d.envelope_changes[0].widenings
    assert "auto-approve enabled" in d.envelope_changes[0].widenings
    assert d.verdict == WIDENED


def test_narrowing_only_change_is_narrowed():
    old = SystemModel(components=[
        _comp("mcp_server.ops", _capabilities=["shell"], _env_has_secrets=True)])
    new = SystemModel(components=[
        _comp("mcp_server.ops", _capabilities=[], _env_has_secrets=False)])
    d = _diff(old, new)
    assert d.envelope_changes[0].narrowings == [
        "capability removed: shell", "secrets cleared from env"]
    assert d.envelope_changes[0].widenings == []
    assert d.verdict == NARROWED


def test_widening_plus_narrowing_is_mixed():
    old = SystemModel(components=[
        _comp("mcp_server.a", _capabilities=["network"]),
        _comp("mcp_server.b"),
    ])
    new = SystemModel(components=[
        _comp("mcp_server.a", _capabilities=[]),
        _comp("mcp_server.b", _capabilities=["shell"]),
    ])
    d = _diff(old, new)
    assert d.verdict == MIXED


# ------------------------------------------------------ cross-boundary edges

def test_cross_boundary_edge_added_widens_and_sentinels_never_count():
    agent = _comp("mcp_server.ops")
    bucket = _comp("aws_s3_bucket.artifacts", ctype="aws_s3_bucket", boundary="cloud")
    peer = _comp("mcp_server.web")
    old = SystemModel(components=[agent, bucket, peer])
    new = SystemModel(
        components=[agent, bucket, peer],
        edges=[
            Edge("mcp_server.ops", "aws_s3_bucket.artifacts", kind="credential_reach"),
            # sentinel and same-boundary edges must not register as crossings
            Edge("mcp_server.ops", "boundary:cloud", kind="tool_access"),
            Edge("mcp_server.ops", "taint:sensitive_action", kind="taint_sink"),
            Edge("mcp_server.ops", "mcp_server.web", kind="references"),
        ],
    )
    d = _diff(old, new)
    assert len(d.crossing_edges_added) == 1
    e = d.crossing_edges_added[0]
    assert (e.source_id, e.target_id, e.kind) == (
        "mcp_server.ops", "aws_s3_bucket.artifacts", "credential_reach")
    assert (e.source_boundary, e.target_boundary) == ("agent_runtime", "cloud")
    assert d.verdict == WIDENED
    # the mirror direction is a narrowing
    assert _diff(new, old).crossing_edges_removed[0].kind == "credential_reach"
    assert _diff(new, old).verdict == NARROWED


# ------------------------------------------------------------- fixture pair

def test_fixture_pair_is_widened_with_all_three_signals_and_the_edge():
    d = _fixture_diff()
    assert d.verdict == WIDENED
    ops = next(c for c in d.envelope_changes if c.id == "mcp_server.ops")
    assert "capability added: shell" in ops.widenings
    assert "secrets now in env" in ops.widenings
    assert "cloud credentials now in env" in ops.widenings
    edges = [(e.source_id, e.target_id, e.kind) for e in d.crossing_edges_added]
    assert ("mcp_server.ops", "aws_s3_bucket.artifacts", "credential_reach") in edges


def test_findings_delta_names_the_newly_firing_rule_ids():
    d = _fixture_diff()
    component_ids = {r.rule_id for r in d.findings_new_component}
    model_ids = {r.rule_id for r in d.findings_new_model}
    assert {"ATL-103", "ATL-112", "ATL-104"} <= component_ids
    assert {"ATL-203", "ATL-207", "ATL-216", "ATL-217"} <= model_ids
    # severities ride along, ranked worst-first within each split
    assert d.findings_new_component[0].rule_id == "ATL-103"
    assert d.findings_new_component[0].severity == "critical"
    assert all(r.component_id.startswith("model") for r in d.findings_new_model)
    # nothing resolved: the widened revision only adds
    assert not d.findings_resolved_component and not d.findings_resolved_model


def test_report_groups_widened_then_findings_with_verdict_last():
    out = render_design_diff(_fixture_diff())
    assert out.index("WIDENED (") < out.index("Findings delta")
    assert out.strip().splitlines()[-1].startswith("verdict: WIDENED - ")


# ---------------------------------------------------------------- CLI + gate

def test_cli_identical_paths_are_unchanged_and_pass_the_gate():
    res = CliRunner().invoke(main, ["design-diff", BASE, BASE, "--fail-on-widen"])
    assert res.exit_code == 0
    assert "verdict: UNCHANGED" in res.output
    assert "No design change" in res.output


def test_cli_fixture_pair_fails_the_gate_with_exit_3():
    res = CliRunner().invoke(main, ["design-diff", BASE, WIDE, "--fail-on-widen"])
    assert res.exit_code == 3
    assert "verdict: WIDENED" in res.output
    assert "widens the agent's reach" in res.output


def test_cli_without_the_gate_reports_but_exits_0():
    res = CliRunner().invoke(main, ["design-diff", BASE, WIDE])
    assert res.exit_code == 0
    assert "verdict: WIDENED" in res.output


def test_cli_narrowing_direction_passes_the_gate():
    res = CliRunner().invoke(main, ["design-diff", WIDE, BASE, "--fail-on-widen"])
    assert res.exit_code == 0
    assert "verdict: NARROWED" in res.output


def test_output_json_round_trips(tmp_path):
    out = tmp_path / "diff.json"
    res = CliRunner().invoke(main, ["design-diff", BASE, WIDE, "-o", str(out)])
    assert res.exit_code == 0 and f"wrote {out}" in res.output
    payload = json.loads(out.read_text())
    assert payload == _fixture_diff().to_dict()
    assert payload["verdict"] == WIDENED
    assert payload["widenings"] and not payload["narrowings"]


def test_diff_is_deterministic_across_runs():
    a, b = _fixture_diff(), _fixture_diff()
    assert a == b
    assert render_design_diff(a) == render_design_diff(b)
    assert a.to_json() == b.to_json()
