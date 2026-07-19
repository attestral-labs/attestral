"""Blast-radius scoring: per-surface if-compromised reach (issue #76)."""
from pathlib import Path

from attestral.aivss import scored
from attestral.blast_radius import (
    annotate_blast_radius,
    blast_radius,
    render_blast_radius,
)
from attestral.ingest import build_model
from attestral.rules import RuleEngine

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def _model(fixture: str):
    return build_model(str(EXAMPLES / fixture))


def test_trifecta_host_outranks_the_leaf():
    # admin-runner holds shell + cloud + database directly; notes holds only
    # memory. The host that concentrates the sinks must top the ranking.
    rows = blast_radius(_model("blast-radius-demo"))
    assert rows, "the demo has tool surfaces to score"
    top = rows[0]
    assert top.name == "admin-runner"
    assert top.score >= 9.0
    # its high-weight sinks are held directly (hop 0), not reached by pivoting.
    assert top.reached["shell"] == 0
    assert top.reached["cloud"] == 0
    assert top.reached["database"] == 0

    leaf = next(b for b in rows if b.name == "notes")
    assert leaf.score < top.score
    assert leaf.reached["memory"] == 0          # its own sink, held directly
    assert leaf.reached["shell"] == 1           # code exec only via a sibling


def test_every_score_is_on_the_zero_to_ten_axis():
    for b in blast_radius(_model("blast-radius-demo")):
        assert 0.0 <= b.score <= 10.0


def test_scoring_is_deterministic():
    m = _model("blast-radius-demo")
    assert blast_radius(m) == blast_radius(m)


def test_a_design_with_no_agent_surface_has_no_blast_radius():
    # A cloud-only design has nothing that can carry an injection, so there is
    # no actor to score - the pass is empty and renders nothing.
    m = _model("aws-pack")
    assert blast_radius(m) == []
    assert render_blast_radius(m, color=False) == ""


def test_render_block_ranks_and_carries_the_honest_caveat():
    block = render_blast_radius(_model("blast-radius-demo"), color=False)
    assert "Blast radius" in block
    assert "admin-runner" in block
    assert "not proof of exploitability" in block


def test_feeds_aivss_only_after_the_pass_runs():
    # Gating invariant: a plain scan never carries the blast-radius factor, so
    # existing AARS scores are unchanged; it appears only once the pass has
    # annotated the components.
    m = _model("blast-radius-demo")
    findings = RuleEngine().evaluate(m)
    before = scored(m, findings)
    assert not any("Extensive blast radius" in a.factors for a, _ in before)

    notes = annotate_blast_radius(m)
    assert notes and "admin-runner" in notes[0]

    after = scored(m, findings)
    assert any("Extensive blast radius" in a.factors for a, _ in after)
    # the factor lands on the high-reach host's own findings, not only the fleet.
    host = [a for a, f in after if f.component_id == "mcp_server.admin-runner"]
    assert host and any("Extensive blast radius" in a.factors for a in host)
