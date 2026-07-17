"""Guard the published ML-layer precision/recall numbers against silent rot.

evaluation/ml-precision-recall.md cites measured numbers. The heuristic tier is
a pure function of the pattern bank and the vendored labeled set, so its floor
is enforceable in CI with no model download. The model tiers are exercised by
`python -m evaluation.ml_eval` on a machine with the extras installed; their
numbers live in evaluation/ml-results.json and the md.

Floors are deliberately below the measured values (precision 0.95, recall 0.14
at the 0.5 default threshold): the gate catches a pattern-bank regression that
tanks the published claim, not normal drift from adding patterns.
"""
from evaluation.ml_eval import LABELED, load_jsonl, metrics, score_text

from attestral.ml import MLConfig, _resolve_engine


def _heuristic_scores() -> list[tuple[float, int]]:
    cfg = MLConfig(engine="heuristic")
    engine, notes = _resolve_engine(cfg)
    assert notes == [], "the heuristic tier must resolve without fallback notes"
    rows = load_jsonl(LABELED)
    return [(score_text(engine, r["text"], cfg), r["label"]) for r in rows]


def test_labeled_set_is_intact():
    rows = load_jsonl(LABELED)
    assert len(rows) == 662
    assert sum(r["label"] for r in rows) == 263
    assert {r["split"] for r in rows} == {"train", "test"}


def test_heuristic_precision_floor_holds():
    m = metrics(_heuristic_scores(), MLConfig().threshold)
    # The heuristic's published story is precision-first. If precision drops
    # below 0.90 on the labeled set, the "high-precision pattern bank" claim
    # in evaluation/ml-precision-recall.md and on the site no longer holds.
    assert m["precision"] >= 0.90, m


def test_heuristic_recall_floor_holds():
    m = metrics(_heuristic_scores(), MLConfig().threshold)
    # Low by design (a curated bank does not chase a generic jailbreak set),
    # but a collapse to near zero would mean the bank stopped matching at all.
    assert m["recall"] >= 0.10, m
