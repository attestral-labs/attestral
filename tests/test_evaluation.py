"""CI guard for the agentic-detection benchmark (evaluation/).

Two properties are enforced so the moat's quality cannot silently rot:
  - recall on labelled positive cases stays at 100% (no rule regresses), and
  - benign designs raise ZERO agentic findings (the false-positive budget is 0).
Coverage and known gaps are reported by `python -m evaluation.score`, not gated
here (coverage debt is tracked, not failed on).
"""
from evaluation.score import run


def test_benchmark_recall_is_full():
    r = run()
    misses = {p["id"]: p["missed"] for p in r["positives"] if p["missed"]}
    assert r["recall"] == 1.0, f"labelled agentic findings regressed: {misses}"


def test_benign_designs_raise_no_agentic_findings():
    r = run()
    noisy = {b["id"]: b["false_positives"] for b in r["benign"] if b["false_positives"]}
    assert r["false_positive_findings"] == 0, f"false positives on benign designs: {noisy}"


def test_coverage_is_reported_and_high():
    r = run()
    # Coverage is tracked, not perfection-gated; guard against a collapse.
    assert r["agentic_rules"] > 0
    assert r["coverage"] >= 0.90, f"agentic coverage dropped to {r['coverage']:.2%}"
