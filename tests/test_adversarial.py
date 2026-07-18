"""Defense-aware evaluation (M10): the adaptive-attack matrix must match reality.

The point of this harness is honesty, so the test protects the honesty: the
recorded matrix has to equal what actually happens today. A robustness claim that
regresses to evaded fails here; a published gap that silently gets fixed also
fails (so the write-up gets updated rather than quietly overstating). The
specific robustness claims and published gaps are asserted by name too, so the
thesis cannot drift even if EXPECTED were edited to match a regression.
"""
from __future__ import annotations

from evaluation.adversarial import run


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


# --- gaps we publish (also gated, so a silent fix updates the doc) ------------

def test_paraphrase_evades_the_language_tier():
    assert _outcome(run()["rows"], "paraphrase") == "evaded"


def test_homoglyph_substitution_evades_the_language_tier():
    assert _outcome(run()["rows"], "homoglyph") == "evaded"


def test_capability_disguise_evades_the_structural_rule():
    rows = run()["rows"]
    assert _outcome(rows, "interpreter") == "evaded"             # shell-out inside JS
    assert _outcome(rows, "opaque wrapper") == "evaded"          # innocuous launcher


def test_evasion_rate_is_reported():
    r = run()
    assert r["adaptive_attacks"] == 8
    assert 0.0 < r["evasion_rate"] < 1.0                          # neither perfect nor useless
