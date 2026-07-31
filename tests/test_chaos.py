"""`attestral chaos`: simulate poisoning attacks against the design's review.

A deterministic, offline red-team harness - it mutates a copy of the scanned
model with a library of poisoning attacks and re-runs Attestral's own detection
over each, reporting CAUGHT vs slipped-through. Doubles as a regression gate for
the whole detection pipeline: if a change breaks any of these detections, chaos
turns red.
"""
import json

from click.testing import CliRunner

from attestral.chaos import (
    ATTACKS,
    ChaosResult,
    chaos_report,
    render_chaos,
    run_chaos,
)
from attestral.cli import main
from attestral.ingest import build_model

FIXTURE = "examples/demo-project"


def test_all_poisoning_attacks_are_caught_by_the_review():
    # Every simulated poisoning class must be flagged - regression confidence for
    # the rules and the zero-dep ML injection tier at once.
    results = run_chaos(build_model(FIXTURE))
    assert len(results) == len(ATTACKS)
    missed = [r.attack.id for r in results if not r.caught]
    assert not missed, f"poisoning attacks slipped through: {missed}"
    by = {r.attack.id: r.by for r in results}
    assert by["shell-smuggle"] == "ATL-103"
    assert by["schema-poisoning"] == "ATL-150"
    assert by["rug-pull"] == "ATL-106"
    assert by["secret-smuggle"] == "ATL-104"
    assert by["tool-poisoning"] == "ml"          # the injection tier catches it
    assert by["injection-evasion"] == "ml"       # robust to zero-width obfuscation


def test_chaos_does_not_mutate_the_original_model():
    model = build_model(FIXTURE)
    n_before = len(model.components)
    run_chaos(model)
    assert len(model.components) == n_before      # each attack ran on a copy


def test_report_shape_and_counts():
    results = run_chaos(build_model(FIXTURE))
    rep = chaos_report(results)
    assert rep["attacks"] == len(ATTACKS)
    assert rep["caught"] == len(ATTACKS)
    assert {r["id"] for r in rep["results"]} == {a.id for a in ATTACKS}


def test_render_marks_a_miss_when_an_attack_slips_through():
    # A hand-built miss exercises the slipped-through render path and copy.
    miss = ChaosResult(ATTACKS[0], caught=False, by="nothing")
    out = render_chaos([miss], color=False)
    assert "MISSED" in out and "1 slipped through" in out


def test_cli_chaos_prints_and_writes_json_only_with_output(tmp_path):
    r = CliRunner().invoke(main, ["chaos", FIXTURE])
    assert r.exit_code == 0, r.output
    assert "simulated poisoning attacks" in r.output
    assert "CAUGHT" in r.output

    out = tmp_path / "chaos.json"
    r2 = CliRunner().invoke(main, ["chaos", FIXTURE, "-o", str(out)])
    assert r2.exit_code == 0
    data = json.loads(out.read_text())
    assert data["attacks"] == len(ATTACKS)


def test_cli_fail_on_miss_gate_is_green_when_all_caught():
    r = CliRunner().invoke(main, ["chaos", FIXTURE, "--fail-on-miss"])
    assert r.exit_code == 0, r.output
