"""Multi-slice eval gate logic (evaluation/eval_slices.py, issue #112).

The regression gate and matrix normalization are pure and deterministic, so
they are tested directly. The model scoring itself (torch) is exercised by the
existing test_ml_eval.py floors; here we pin the gate's fail-closed behavior.
"""
import json
from pathlib import Path

from attestral.ml import MLConfig

from evaluation.eval_slices import SLICES, check_regression, evaluate
from evaluation.ml_eval import build_engine

BASELINE = Path(__file__).resolve().parents[1] / "evaluation" / "data" / "ml-slice-baseline.json"


def _base() -> dict:
    """A frozen baseline covering every slice; over_defense has no recall."""
    b = {name: {"recall": 0.9, "fp_rate": 0.0, "n_pos": 10, "n_neg": 10,
                "false_positives": 0} for name in SLICES}
    b["over_defense"] = {"recall": None, "fp_rate": 0.0, "n_pos": 0,
                         "n_neg": 32, "false_positives": 0}
    return b


def test_identical_results_have_no_regression():
    base = _base()
    assert check_regression(base, base) == []


def test_recall_drop_beyond_tolerance_is_a_regression():
    base = _base()
    cur = _base()
    cur["paraphrase"]["recall"] = 0.80          # 0.10 below, tol 0.05
    v = check_regression(cur, base, tol=0.05)
    assert any("paraphrase" in s and "recall" in s for s in v)


def test_recall_drop_within_tolerance_passes():
    base = _base()
    cur = _base()
    cur["paraphrase"]["recall"] = 0.87          # 0.03 below, within tol
    assert check_regression(cur, base, tol=0.05) == []


def test_fp_rate_rise_beyond_tolerance_is_a_regression():
    base = _base()
    cur = _base()
    cur["over_defense"]["fp_rate"] = 0.20       # benign-only slice still gated on FP
    v = check_regression(cur, base, tol=0.05)
    assert any("over_defense" in s and "fp_rate" in s for s in v)


def test_missing_slice_fails_closed():
    base = _base()
    cur = _base()
    del cur["multilingual"]
    v = check_regression(cur, base)
    assert any("multilingual" in s and "missing" in s for s in v)


def test_over_defense_recall_none_never_trips_recall_check():
    base = _base()
    cur = _base()
    # both None-recall; only fp_rate should ever be judged for this slice
    assert cur["over_defense"]["recall"] is None
    assert check_regression(cur, base) == []


def test_heuristic_slices_hold_the_committed_baseline():
    """The zero-dependency heuristic tier is deterministic, so its multi-slice
    numbers are a CI gate: a pattern-bank change that regresses any slice fails
    here until the baseline is deliberately re-frozen."""
    cfg = MLConfig(engine="heuristic")
    engine = build_engine("heuristic", cfg)
    results = evaluate(engine, cfg)
    baseline = json.loads(BASELINE.read_text())
    assert check_regression(results, baseline, tol=0.05) == []
