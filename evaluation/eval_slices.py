"""Continuous multi-slice evaluation and regression gate for the ML tier (#112).

The ML tier is now trainable on our own data (the weak-supervision loop, #81),
so it will change over time. We already keep five labeled slices, each encoding
a distinct failure mode:

    deepset       the independent injection/benign reference set
    paraphrase    injections the heuristic is blind to (the model tier's job)
    obfuscation   leetspeak / separator-spread / encoded injections
    multilingual  the instruction-override family in eight non-English languages
    over_defense  benign text carrying trigger words (the false-positive trap)

Scoring one of them at a time hides trade-offs: a retrain that lifts paraphrase
recall while quietly regressing the over-defense false-positive rate would ship
unnoticed. This scores a given engine or model across ALL of them at once,
prints one matrix, and can freeze a baseline and fail on any regression, the
same shape as the ecosystem regression gate.

    python -m evaluation.eval_slices --engine heuristic
    python -m evaluation.eval_slices --engine deberta --model ./attestral-injection-v1
    python -m evaluation.eval_slices --engine deberta --baseline base.json   # freeze
    python -m evaluation.eval_slices --engine deberta --model ./v1 --check base.json

Every slice goes through the same production scoring path as `attestral scan
--ml`, including the surface-aware muting, so the numbers are what the tool
actually reports. Reuses the slice functions in evaluation.ml_eval; adds only
the cross-slice matrix and the gate.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from attestral.ml import MLConfig

from evaluation.ml_eval import (
    LABELED,
    _labeled_slice,
    build_engine,
    multilingual_slice,
    obfuscation_slice,
    over_defense_slice,
    paraphrase_slice,
)

# Each slice normalized to a common {recall, fp_rate, n_pos, n_neg} shape. The
# over-defense slice is benign-only, so its recall is not defined (None) and the
# gate judges it on the false-positive rate alone.
SLICES = ("deepset", "paraphrase", "obfuscation", "multilingual", "over_defense")


def _slice_metrics(name: str, engine, cfg: MLConfig) -> dict:
    if name == "deepset":
        s = _labeled_slice(engine, cfg, LABELED)
    elif name == "paraphrase":
        s = paraphrase_slice(engine, cfg)
    elif name == "obfuscation":
        s = obfuscation_slice(engine, cfg)
    elif name == "multilingual":
        s = multilingual_slice(engine, cfg)
    elif name == "over_defense":
        s = over_defense_slice(engine, cfg)
    else:  # unreachable: SLICES is the closed set
        raise ValueError(name)

    if name == "over_defense":
        return {"recall": None, "fp_rate": s["fp_rate"],
                "n_pos": 0, "n_neg": s["n"], "false_positives": s["false_positives"]}
    return {"recall": s["recall"], "fp_rate": s["fp_rate"],
            "n_pos": s["n_pos"], "n_neg": s["n_neg"],
            "false_positives": s["false_positives"]}


def evaluate(engine, cfg: MLConfig) -> dict:
    """Score every slice, returning {slice: metrics}."""
    return {name: _slice_metrics(name, engine, cfg) for name in SLICES}


def check_regression(results: dict, baseline: dict, tol: float = 0.05) -> list[str]:
    """Regressions of `results` against a frozen `baseline`: recall must not drop
    more than `tol` below baseline, and fp_rate must not rise more than `tol`
    above it. A slice missing from either side is reported, never silently
    passed (fail closed). Returns human-readable violation strings."""
    violations: list[str] = []
    for name in SLICES:
        cur, base = results.get(name), baseline.get(name)
        if cur is None or base is None:
            violations.append(f"{name}: missing from {'results' if cur is None else 'baseline'}")
            continue
        if base.get("recall") is not None and cur.get("recall") is not None:
            if cur["recall"] < base["recall"] - tol:
                violations.append(
                    f"{name}: recall {cur['recall']:.3f} < baseline "
                    f"{base['recall']:.3f} - {tol}")
        if cur["fp_rate"] > base["fp_rate"] + tol:
            violations.append(
                f"{name}: fp_rate {cur['fp_rate']:.3f} > baseline "
                f"{base['fp_rate']:.3f} + {tol}")
    return violations


def print_matrix(results: dict, label: str = "") -> None:
    head = f"  slice{'':>9}recall      fp_rate     support"
    print(f"\n== multi-slice eval {label}".rstrip())
    print(head)
    for name in SLICES:
        m = results[name]
        rec = "    -   " if m["recall"] is None else f"{m['recall']:.3f}   "
        support = f"{m['n_pos']}+/{m['n_neg']}-"
        print(f"  {name:<13} {rec}     {m['fp_rate']:.3f} "
              f"({m['false_positives']}/{m['n_neg']})   {support}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--engine", default="heuristic",
                    choices=["heuristic", "onnx", "deberta"],
                    help="Which tier to score (default: heuristic).")
    ap.add_argument("--model", default=None,
                    help="Model id or local dir to score (e.g. a fine-tuned output). "
                         "Defaults to the shipped injection model.")
    ap.add_argument("--revision", default="main")
    ap.add_argument("--threshold", type=float, default=MLConfig().threshold)
    ap.add_argument("--baseline", default=None,
                    help="Write the current results to this JSON as the frozen baseline.")
    ap.add_argument("--check", default=None,
                    help="Fail (exit 1) if the current results regress against this baseline JSON.")
    ap.add_argument("--tol", type=float, default=0.05, help="Regression tolerance.")
    args = ap.parse_args()

    cfg = MLConfig(engine=args.engine, threshold=args.threshold, revision=args.revision)
    if args.model:
        cfg.model = args.model
    engine = build_engine(args.engine, cfg)
    if engine is None:
        raise SystemExit(f"engine '{args.engine}' is unavailable (missing deps or weights)")

    results = evaluate(engine, cfg)
    print_matrix(results, label=f"[{args.engine}{' ' + args.model if args.model else ''}]")

    if args.baseline:
        Path(args.baseline).write_text(json.dumps(results, indent=2) + "\n")
        print(f"\nfroze baseline -> {args.baseline}")

    if args.check:
        baseline = json.loads(Path(args.check).read_text())
        violations = check_regression(results, baseline, args.tol)
        if violations:
            print(f"\nREGRESSION vs {args.check}:")
            for v in violations:
                print(f"  - {v}")
            raise SystemExit(1)
        print(f"\nno regression vs {args.check} (tol {args.tol})")


if __name__ == "__main__":
    main()
