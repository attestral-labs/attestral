"""A label model over Attestral's detectors (#111): weak supervision, upgraded.

`label.py` uses a single labeling function, the aggregate heuristic score, with
one hard band. That is the simplest weak-supervision setup and it leaves signal
on the table, because the heuristic is really several independent detectors and
a single 0.90 band only mints a positive when the aggregate is very confident.

This decomposes the detector stack into a set of labeling functions (LFs) that
each vote +1 (injection), -1 (benign), or 0 (abstain) on a surface, then
combines their votes into one probability with a lightweight Snorkel-style label
model: each LF is weighted by its estimated accuracy (Naive-Bayes log-odds), so
a precise LF counts for more than a noisy one, and the positive detectors and
the benign voters partition the work. The positive LFs fire on distinct
injection families (override, exfiltration, jailbreak, tool poisoning, control
tags) plus two structurally orthogonal channels (hidden unicode, and payloads
revealed only after decode/de-obfuscation), so their errors are largely
independent, which is the condition under which a label model beats any single
LF.

Zero dependency: pure Python over `attestral.ml`'s detectors. Accuracies are
learned from a small gold set when one is available, or unsupervised from the
LFs' agreement structure (a compact Dawid-Skene-style iteration) when it is not.

    python labelmodel.py --data ../evaluation/data/deepset-prompt-injections.jsonl

prints the label model's coverage / precision / recall against gold next to the
single-heuristic-LF band it replaces.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

from attestral.ml import (
    _HIDDEN_UNICODE,
    _decoded_encodings,
    _decoded_payloads,
    _deconfuse,
    _deobfuscate,
    _match_categories,
    heuristic_score,
)

# Positive LFs fire +1 on their family and abstain otherwise, so absence of one
# injection type is never miscounted as evidence of benignity. Two benign LFs
# supply the negative class. A vote is +1 / -1 / 0 (abstain).
_POS_FAMILIES = {
    "lf_override": ("instruction_override", "multilingual_override"),
    "lf_exfil": ("data_exfiltration", "system_prompt_exfil"),
    "lf_jailbreak": ("jailbreak_persona",),
    "lf_tool_poisoning": ("tool_poisoning",),
    "lf_control_tags": ("injected_control_tags",),
}


def _category_lf(text: str, families: tuple[str, ...]) -> int:
    cats = _match_categories(text)
    return 1 if any(f in cats for f in families) else 0


def lf_hidden_channel(text: str) -> int:
    """Zero-width / bidi control characters: a hiding channel with no benign
    reason to appear in a tool description. Orthogonal to the language LFs.
    Gated on the same matcher heuristic_score uses, not the describer (which
    always returns a non-empty label)."""
    return 1 if _HIDDEN_UNICODE.search(text) else 0


def lf_decoded(text: str) -> int:
    """A base64 / hex / decimal / URL-encoded blob that decodes to an injection
    family. Only a decoded payload that itself matches a family votes, so a
    benign encoded id never fires."""
    for dec in _decoded_payloads(text) + _decoded_encodings(text):
        if _match_categories(dec):
            return 1
    return 0


def lf_deobfuscated(text: str) -> int:
    """A family that appears only after leetspeak / homoglyph normalization,
    i.e. a payload the visible text hid. Votes only when de-obfuscation REVEALS
    a family the raw text lacked, so plain text is a no-op."""
    raw = set(_match_categories(text))
    revealed = set(_match_categories(_deobfuscate(_deconfuse(text))))
    return 1 if revealed - raw else 0


def lf_clean(text: str) -> int:
    """Benign voter: a surface the aggregate heuristic scores at zero with no
    family match is weak evidence of benignity."""
    score, _ = heuristic_score(text)
    return -1 if score == 0.0 and not _match_categories(text) else 0


_IMPERATIVE = ("ignore", "disregard", "override", "forget", "instead", "you are now",
               "system:", "execute", "reveal", "exfiltrate", "send", "must", "do not tell")


def lf_no_command(text: str) -> int:
    """Benign voter: a short surface with no imperative / second-person command
    shape and none of the coarse trigger words. Deliberately conservative so it
    abstains rather than mislabel anything instruction-like."""
    low = (text or "").lower()
    if len(low) > 600:
        return 0  # long text is too likely to contain something; abstain
    return -1 if not any(t in low for t in _IMPERATIVE) else 0


def _labeling_functions():
    lfs = [(name, lambda t, f=fams: _category_lf(t, f)) for name, fams in _POS_FAMILIES.items()]
    lfs += [
        ("lf_hidden_channel", lf_hidden_channel),
        ("lf_decoded", lf_decoded),
        ("lf_deobfuscated", lf_deobfuscated),
        ("lf_clean", lf_clean),
        ("lf_no_command", lf_no_command),
    ]
    return lfs


LF_NAMES = [name for name, _ in _labeling_functions()]


def vote_matrix(texts: list[str]) -> list[list[int]]:
    """Rows are surfaces, columns are LF votes in LF_NAMES order."""
    lfs = _labeling_functions()
    return [[fn(t) for _, fn in lfs] for t in texts]


def _clamp(a: float, lo: float = 0.55, hi: float = 0.99) -> float:
    return max(lo, min(hi, a))


def fit_accuracies(votes: list[list[int]], gold: list[int] | None = None,
                   iters: int = 5) -> list[float]:
    """Per-LF accuracy. With gold labels, the fraction of firing votes that
    match the label. Without gold, a Dawid-Skene-style loop: seed with the
    unweighted vote sign, estimate each LF's accuracy against it, re-predict
    with those weights, repeat. Clamped away from 0 and 1 so one LF can never
    dominate."""
    n_lf = len(votes[0]) if votes else 0
    if gold is not None:
        labels = gold
    else:
        labels = [1 if sum(row) > 0 else 0 for row in votes]  # seed: majority sign
    for _ in range(1 if gold is not None else iters):
        acc = []
        for j in range(n_lf):
            fired = [(row[j], labels[i]) for i, row in enumerate(votes) if row[j] != 0]
            if not fired:
                acc.append(0.55)
                continue
            correct = sum(1 for v, y in fired if (v > 0) == (y == 1))
            acc.append(_clamp(correct / len(fired)))
        if gold is not None:
            return acc
        weights = [math.log(a / (1 - a)) for a in acc]
        labels = [1 if _logit(row, weights) >= 0 else 0 for row in votes]
    return acc


def _logit(row: list[int], weights: list[float]) -> float:
    return sum(w * v for w, v in zip(weights, row))


def predict_proba(votes: list[list[int]], accuracies: list[float]) -> list[float]:
    """P(injection) per surface: sigmoid of the accuracy-weighted vote sum."""
    weights = [math.log(a / (1 - a)) for a in accuracies]
    return [1.0 / (1.0 + math.exp(-_logit(row, weights))) for row in votes]


class LabelModel:
    """Fit accuracies once, then score any surface. Provenance-friendly: the
    per-LF accuracies are the model, small and inspectable."""

    def __init__(self) -> None:
        self.accuracies: list[float] | None = None

    def fit(self, texts: list[str], gold: list[int] | None = None) -> "LabelModel":
        self.accuracies = fit_accuracies(vote_matrix(texts), gold)
        return self

    def proba(self, texts: list[str]) -> list[float]:
        if self.accuracies is None:
            raise RuntimeError("call fit() before proba()")
        return predict_proba(vote_matrix(texts), self.accuracies)


def _metrics(pred_pos: list[bool], abstain: list[bool], gold: list[int]) -> dict:
    labeled = [i for i in range(len(gold)) if not abstain[i]]
    tp = sum(1 for i in labeled if pred_pos[i] and gold[i] == 1)
    fp = sum(1 for i in labeled if pred_pos[i] and gold[i] == 0)
    fn = sum(1 for i in range(len(gold)) if gold[i] == 1 and (abstain[i] or not pred_pos[i]))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"coverage": round(len(labeled) / len(gold), 4) if gold else 0.0,
            "precision": round(prec, 4), "recall": round(rec, 4)}


def compare_on_gold(texts: list[str], gold: list[int], pos: float = 0.9,
                    neg: float = 0.05, lm_hi: float = 0.6, lm_lo: float = 0.4) -> dict:
    """Single-heuristic-LF band vs the label model on a gold set. The single LF
    only mints a label outside [neg, pos]; the label model abstains only in the
    uncertain middle [lm_lo, lm_hi]. Reports coverage/precision/recall for each,
    the honest way to see whether the ensemble labels more at equal precision."""
    single_scores = [heuristic_score(t)[0] for t in texts]
    single_pos = [s >= pos for s in single_scores]
    single_abstain = [neg < s < pos for s in single_scores]

    lm = LabelModel().fit(texts, gold)
    lm_p = lm.proba(texts)
    lm_pos = [p >= lm_hi for p in lm_p]
    lm_abstain = [lm_lo < p < lm_hi for p in lm_p]

    return {
        "single_heuristic_lf": _metrics(single_pos, single_abstain, gold),
        "label_model": _metrics(lm_pos, lm_abstain, gold),
        "accuracies": {n: round(a, 3) for n, a in zip(LF_NAMES, lm.accuracies)},
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", required=True, help="Labeled JSONL ({text,label}).")
    args = ap.parse_args()
    rows = [json.loads(x) for x in Path(args.data).read_text().splitlines() if x.strip()]
    texts = [str(r["text"]) for r in rows]
    gold = [int(r["label"]) for r in rows]
    out = compare_on_gold(texts, gold)

    print(f"\nlabel model vs single heuristic LF on {len(rows)} gold rows "
          f"({sum(gold)} injection / {len(gold) - sum(gold)} benign)\n")
    print(f"  {'labeler':<22} {'coverage':>9} {'precision':>10} {'recall':>8}")
    for name in ("single_heuristic_lf", "label_model"):
        m = out[name]
        print(f"  {name:<22} {m['coverage']:>9.3f} {m['precision']:>10.3f} {m['recall']:>8.3f}")
    print("\n  learned LF accuracies:")
    for n, a in out["accuracies"].items():
        print(f"    {n:<20} {a:.3f}")


if __name__ == "__main__":
    main()
