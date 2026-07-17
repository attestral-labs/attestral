"""Measure the ML layer's precision/recall on labeled injection data.

Two measurements, mirroring the rules benchmark's two tiers:

1. **Independent labeled set** (`data/deepset-prompt-injections.jsonl`,
   vendored from the Apache-2.0 `deepset/prompt-injections` dataset, 662
   rows): precision / recall / F1 per installed tier at the shipped default
   threshold, plus a threshold sweep. The base DeBERTa model's published
   training mix does not list this dataset, so it is an out-of-training-set
   read for the model tier and a fully independent one for the heuristic.
2. **Real MCP surfaces** (`--repos <dir>`): every text surface Attestral's
   own ingest extracts from a directory of real MCP server repos - the
   false-positive read on surfaces nobody wrote to be scanned. Flagged
   surfaces are printed in full for human adjudication; a flag here is not
   automatically a false positive.

Scoring goes through the production code path (`MLConfig`, `_resolve_engine`,
`_chunks`: a surface's score is its max chunk probability), so the numbers
measure what `attestral scan --ml` actually does, not a lab shortcut. A tier
whose dependencies are not installed is reported as skipped, never silently
degraded to the heuristic.

    python -m evaluation.ml_eval                     # labeled set, installed tiers
    python -m evaluation.ml_eval --engine heuristic  # a single tier
    python -m evaluation.ml_eval --repos research/mcp-ecosystem/work

Writes `evaluation/ml-results.json` next to this file. The published write-up
lives in `evaluation/ml-precision-recall.md`.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from attestral.ml import MLConfig, _chunks, _resolve_engine, muted_on_surface

HERE = Path(__file__).resolve().parent
LABELED = HERE / "data" / "deepset-prompt-injections.jsonl"
RESULTS = HERE / "ml-results.json"

TIERS = ["heuristic", "onnx", "deberta"]


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text().splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def build_engine(tier: str, cfg: MLConfig):
    """Resolve one tier through the production ladder, or None if unavailable."""
    tier_cfg = MLConfig(
        model=cfg.model, revision=cfg.revision, engine=tier,
        threshold=cfg.threshold, max_chars=cfg.max_chars,
        overlap=cfg.overlap, device=cfg.device,
    )
    engine, notes = _resolve_engine(tier_cfg)
    if tier != "heuristic" and notes:
        return None  # would have degraded to the heuristic: report, don't fake
    return engine


def score_text(engine, text: str, cfg: MLConfig) -> float:
    """A surface's score is its max chunk probability, as in ml.scan()."""
    best = 0.0
    for chunk in _chunks(text, cfg.max_chars, cfg.overlap):
        prob, _ = engine(chunk)
        best = max(best, prob)
    return best


def score_surface(engine, text: str, cfg: MLConfig) -> tuple[float, set[str]]:
    """Max chunk probability plus pooled evidence categories, as in ml.scan()."""
    best, cats = 0.0, set()
    for chunk in _chunks(text, cfg.max_chars, cfg.overlap):
        prob, ev = engine(chunk)
        cats.update(e.split(":", 1)[0] for e in ev)
        best = max(best, prob)
    return best, cats


def metrics(scored: list[tuple[float, int]], threshold: float) -> dict:
    tp = sum(1 for p, y in scored if p >= threshold and y == 1)
    fp = sum(1 for p, y in scored if p >= threshold and y == 0)
    fn = sum(1 for p, y in scored if p < threshold and y == 1)
    tn = sum(1 for p, y in scored if p < threshold and y == 0)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {
        "threshold": threshold, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4),
    }


def gather_repo_surfaces(repos_dir: Path) -> list[dict]:
    """Extract every scored text surface from each repo, deduplicated by text."""
    from attestral.ingest import build_model
    from attestral.ml import gather_surfaces

    rows, seen = [], set()
    for repo in sorted(p for p in repos_dir.iterdir() if p.is_dir()):
        try:
            model = build_model(str(repo))
        except Exception as exc:  # a broken vendored repo shouldn't sink the run
            print(f"  [skip] {repo.name}: {exc}")
            continue
        for s in gather_surfaces(model):
            if s.text in seen:
                continue
            seen.add(s.text)
            rows.append({"repo": repo.name, "surface": s.label, "text": s.text,
                         "ctype": s.component_type})
    return rows


def run(engines: list[str], cfg: MLConfig, repos_dir: Path | None) -> dict:
    labeled = load_jsonl(LABELED)
    pos = sum(r["label"] for r in labeled)
    print(f"labeled set: {len(labeled)} rows ({pos} injection / {len(labeled) - pos} benign)")

    surfaces = gather_repo_surfaces(repos_dir) if repos_dir else []
    if repos_dir:
        print(f"real surfaces: {len(surfaces)} unique texts from {repos_dir}")

    # Merge into any existing results file so single-tier runs (e.g. the torch
    # tier on a beefier machine) don't clobber the other tiers' numbers.
    out: dict = {"labeled_rows": len(labeled), "positives": pos,
                 "default_threshold": cfg.threshold, "tiers": {}}
    if RESULTS.is_file():
        try:
            prev = json.loads(RESULTS.read_text())
            if prev.get("labeled_rows") == len(labeled):
                out["tiers"] = prev.get("tiers", {})
        except (ValueError, KeyError):
            pass
    for tier in engines:
        engine = build_engine(tier, cfg)
        if engine is None:
            print(f"\n== {tier}: SKIPPED (dependencies or weights not installed)")
            out["tiers"][tier] = {"skipped": True}
            continue

        scored = [(score_text(engine, r["text"], cfg), r["label"]) for r in labeled]
        at_default = metrics(scored, cfg.threshold)
        sweep = [metrics(scored, t / 10) for t in range(1, 10)]
        # Per-row scores go into the artifact so any slice (split, language,
        # length) can be re-analyzed without re-running the model.
        row_scores = [round(p, 4) for p, _ in scored]

        print(f"\n== {tier} @ threshold {cfg.threshold}")
        print(f"   precision {at_default['precision']:.3f}  recall {at_default['recall']:.3f}"
              f"  f1 {at_default['f1']:.3f}  (tp {at_default['tp']} fp {at_default['fp']}"
              f" fn {at_default['fn']} tn {at_default['tn']})")

        tier_out = {"labeled": at_default, "sweep": sweep, "row_scores": row_scores}
        prior = out["tiers"].get(tier) or {}
        if not surfaces and "real_surfaces" in prior:
            tier_out["real_surfaces"] = prior["real_surfaces"]  # keep the FP read
        if surfaces:
            flagged = []
            for s in surfaces:
                # Same surface-aware muting as ml.scan(), so the read measures
                # what `attestral scan --ml` actually reports.
                p, cats = score_surface(engine, s["text"], cfg)
                if p >= cfg.threshold and not muted_on_surface(s.get("ctype", ""), cats):
                    flagged.append({**s, "score": round(p, 4)})
            rate = len(flagged) / len(surfaces) if surfaces else 0.0
            print(f"   real surfaces flagged: {len(flagged)}/{len(surfaces)} ({rate:.1%})")
            for f in flagged:
                flat = " ".join(f["text"].split())
                print(f"     - [{f['score']:.2f}] {f['repo']} / {f['surface']}: {flat[:160]}")
            tier_out["real_surfaces"] = {
                "total": len(surfaces), "flagged": len(flagged),
                "rate": round(rate, 4), "flagged_items": flagged,
            }
        out["tiers"][tier] = tier_out

    RESULTS.write_text(json.dumps(out, indent=2, ensure_ascii=False) + "\n")
    print(f"\nwrote {RESULTS.relative_to(HERE.parent)}")
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--engine", choices=TIERS, help="Run a single tier (default: all installed).")
    ap.add_argument("--repos", type=Path,
                    help="Directory of real MCP repos for the false-positive read.")
    ap.add_argument("--threshold", type=float, default=MLConfig().threshold)
    args = ap.parse_args()
    cfg = MLConfig(threshold=args.threshold)
    run([args.engine] if args.engine else TIERS, cfg, args.repos)


if __name__ == "__main__":
    main()
