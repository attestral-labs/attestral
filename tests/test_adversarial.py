"""Defense-aware evaluation (M10): the adaptive-attack matrix must match reality.

The point of this harness is honesty, so the test protects the honesty: the
recorded matrix has to equal what actually happens today. A robustness claim that
regresses to evaded fails here; a published gap that silently gets fixed also
fails (so the write-up gets updated rather than quietly overstating). The
specific robustness claims and published gaps are asserted by name too, so the
thesis cannot drift even if EXPECTED were edited to match a regression.
"""
from __future__ import annotations

import pytest

from evaluation.adversarial import EXPECTED_DEBERTA, run


def _outcome(rows, attack_substr: str) -> str:
    hits = [r for r in rows if attack_substr in r["attack"]]
    assert len(hits) == 1, f"expected one case matching {attack_substr!r}, got {len(hits)}"
    return hits[0]["outcome"]


def test_recorded_matrix_matches_reality():
    # The single tightest gate: nothing in the published matrix diverged from a
    # live scan. Covers every robustness claim and every published gap at once.
    assert run()["diverged"] == []


def test_controls_are_detected():
    rows = run()["rows"]
    for control in ("language | identity", "shell / declared", "trifecta / one config"):
        # controls use the substring before the outcome column
        key = control.split(" | ")[-1]
        assert _outcome(rows, key) == "detected"


# --- robustness we claim (gated) ----------------------------------------------

def test_obfuscation_the_heuristic_decodes_is_robust():
    rows = run()["rows"]
    assert _outcome(rows, "base64-encoded") == "detected"        # payload decoder
    assert _outcome(rows, "zero-width") == "detected"            # hidden-unicode detector


def test_fleet_model_is_robust_to_env_prefix_and_file_split():
    rows = run()["rows"]
    assert _outcome(rows, "env-prefixed") == "detected"          # bash token still in argv
    assert _outcome(rows, "split across two files") == "detected"  # whole-repo fleet model


# --- gaps we closed after M10 (gated, so a regression fails) ------------------

def test_homoglyph_substitution_is_now_normalized():
    # Closed by confusables normalization in the ML heuristic.
    assert _outcome(run()["rows"], "homoglyph") == "detected"


def test_interpreter_shellout_is_now_caught():
    # Closed by ATL-146 (shell hidden in interpreter inline code).
    assert _outcome(run()["rows"], "interpreter") == "detected"


# --- gaps that remain, and why (also gated, so a silent fix updates the doc) --

def test_paraphrase_still_evades_the_heuristic_tier():
    # Semantic rewording is the DeBERTa tier's job, not the heuristic's.
    assert _outcome(run()["rows"], "paraphrase") == "evaded"


def test_opaque_wrapper_still_evades():
    # Seeing that `uvx toolrunner` shells out needs the package body (runtime loop).
    assert _outcome(run()["rows"], "opaque wrapper") == "evaded"


def test_evasion_rate_dropped_after_mitigations():
    r = run()
    assert r["adaptive_attacks"] == 8
    assert r["evaded"] == 2                                       # down from 4 (homoglyph + interpreter closed)
    assert 0.0 < r["evasion_rate"] < 1.0                          # honest: not perfect, not useless


# --- the DeBERTa tier escalation (measured only when attestral[ml] is present) -
# The escalation loads the model, so compute it once for the module and let the
# heuristic-only tests above stay model-free.

@pytest.fixture(scope="module")
def escalation() -> dict:
    return run(escalate=True)["tier_escalation"]


def test_escalation_matrix_is_wellformed(escalation):
    # Every language attack has a recorded DeBERTa expectation, installed or not.
    assert {r["attack"] for r in escalation["rows"]} == set(EXPECTED_DEBERTA)
    for row in escalation["rows"]:
        assert row["tier"] == "deberta"
        assert row["outcome"] in {"detected", "evaded", "unavailable"}


def test_escalation_matches_recorded_matrix_when_present(escalation):
    if not escalation["available"]:
        pytest.skip("attestral[ml] not installed; DeBERTa escalation not measured")
    assert escalation["diverged"] == []                           # no divergence from EXPECTED_DEBERTA


def test_escalation_closes_paraphrase_but_not_base64_when_present(escalation):
    # The point of the tier: it closes the semantic paraphrase the heuristic is
    # blind to, and it is complementary, not strictly better - it misses the
    # base64 payload the heuristic decodes.
    if not escalation["available"]:
        pytest.skip("attestral[ml] not installed; DeBERTa escalation not measured")
    out = {r["attack"]: r["outcome"] for r in escalation["rows"]}
    assert out["paraphrase"] == "detected"
    assert out["base64-encoded"] == "evaded"
