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


def test_structural_and_evasion_attacks_are_caught():
    # Regression confidence: the rules catch the structural poisonings and the
    # ML tier catches the whole character-injection evasion family at once.
    results = run_chaos(build_model(FIXTURE))
    assert len(results) == len(ATTACKS)
    by = {r.attack.id: r.by for r in results}
    assert by["shell-smuggle"] == "ATL-103"
    assert by["schema-poisoning"] == "ATL-150"
    assert by["rug-pull"] == "ATL-106"
    assert by["secret-smuggle"] == "ATL-104"
    for evasion in ("tool-poisoning", "injection-evasion", "homoglyph",
                    "base64-payload", "bidi-override"):
        assert by[evasion] == "ml", evasion


def test_canonicalization_closes_the_invisible_character_gaps():
    # Regression guard for the canonicalization extension: an injection smuggled
    # through the Unicode Tags block or emoji variation selectors is caught.
    by = {r.attack.id: (r.caught, r.by) for r in run_chaos(build_model(FIXTURE))}
    assert by["tags-stego"] == (True, "ml")
    assert by["emoji-stego"] == (True, "ml")


def test_split_payload_is_caught_only_by_fleet_scoring():
    # The ShareLock split is invisible per-tool and visible to the system model.
    by = {r.attack.id: (r.caught, r.by) for r in run_chaos(build_model(FIXTURE))}
    assert by["split-payload"] == (True, "ml (fleet)")


def test_schema_default_is_a_tracked_open_gap():
    # Honest: the ML tier does not yet enumerate every schema string field, so
    # this one slips through. The harness reports it rather than hiding it.
    results = run_chaos(build_model(FIXTURE))
    missed = [r.attack.id for r in results if not r.caught]
    assert missed == ["schema-default"]


def test_chaos_does_not_mutate_the_original_model():
    model = build_model(FIXTURE)
    n_before = len(model.components)
    run_chaos(model)
    assert len(model.components) == n_before      # each attack ran on a copy


def test_report_shape_and_counts():
    results = run_chaos(build_model(FIXTURE))
    rep = chaos_report(results)
    assert rep["attacks"] == len(ATTACKS)
    assert rep["caught"] == len(ATTACKS) - 1        # all but the tracked schema-default gap
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


def test_cli_fail_on_miss_gate_flags_the_open_gap():
    # --fail-on-miss is a robustness gate; the tracked schema-default gap trips it.
    r = CliRunner().invoke(main, ["chaos", FIXTURE, "--fail-on-miss"])
    assert r.exit_code == 1
    assert "schema-default" in r.output
