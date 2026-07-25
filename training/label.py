"""Rules as labeler: weak-supervision label generation for the ML tier (#81).

The ML layer ships a fine-tuned DeBERTa injection classifier. Fine-tuning it on
*our* distribution needs labeled MCP surfaces, and hand-labeling tens of
thousands of tool descriptions is exactly the cost that stops most teams. This
script removes that cost by using Attestral's own zero-dependency heuristic
detector as the labeling function, Snorkel-style:

    corpus of real MCP configs
        -> gather every text surface (tool + server descriptions)
        -> score each with attestral.ml.heuristic_score  (the labeler)
        -> high score  => weak positive (injection)      label 1
           near zero   => weak negative (benign)          label 0
           in between   => ABSTAIN, routed to a review queue
        -> dedupe, split, write train/eval/review JSONL

The abstain band is the point, not an afterthought: weak labels inherit the
labeler's blind spots, so the uncertain middle (and, with --model, the places
where a trained model already disagrees with the heuristic) are the highest
value examples for a human to label by hand. The deterministic layer stays the
audit ground truth; this only mints *training* labels, never findings.

The fine-tune generalizes past the heuristic's exact patterns - that gain is
measured on evaluation/data/paraphrase-injections.jsonl by training/evaluate.py.

Zero dependency by default (only the attestral package, itself dep-light). The
optional --model disagreement pass lazily imports the ML tier's classifier.

    python label.py --corpus ../research/mcp-ecosystem --out data
    python finetune.py --train data/train.jsonl --eval data/eval.jsonl --out ./model

This lives outside the attestral package with the other training scripts; the
tool never imports it.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from attestral.ingest.scan import build_model
from attestral.ml import gather_surfaces, heuristic_score

# Default label bands. The positive bar is deliberately high: a weak positive
# should be one the heuristic is confident about, because a wrong positive
# teaches the model to cry wolf. The negative bar is near zero for the same
# reason in reverse. Everything between abstains to the review queue.
POS_THRESHOLD = 0.90
NEG_THRESHOLD = 0.05

# Filenames that mark a repo we should ingest. A static MCP config is mostly
# launch commands (little language), so the rich injection surfaces are the
# instruction and agent files build_model reads alongside it: system prompts,
# CLAUDE.md-style rules, skill manifests, code-defined agents.
_UNIT_MARKERS = {
    ".mcp.json", "mcp.json", "claude_desktop_config.json",
    "CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules",
    ".clauderules", "copilot-instructions.md",
}


def band(prob: float, pos: float = POS_THRESHOLD, neg: float = NEG_THRESHOLD) -> int | None:
    """Weak label for a heuristic score: 1 positive, 0 negative, None abstain."""
    if prob >= pos:
        return 1
    if prob <= neg:
        return 0
    return None


def norm_key(text: str) -> str:
    """Dedup key: whitespace-collapsed, casefolded. Two surfaces that differ
    only in spacing or case are the same training example, and letting a near
    duplicate land in both splits would overstate eval accuracy."""
    return " ".join((text or "").split()).casefold()


def split_of(key: str, eval_pct: int) -> str:
    """Deterministic train/eval assignment by hashing the dedup key, so a given
    text always lands in the same split (no RNG, reproducible, and duplicates
    can never straddle the split). eval_pct in [0, 100]."""
    bucket = int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) % 100
    return "eval" if bucket < eval_pct else "train"


def iter_units(corpus: Path) -> list[Path]:
    """The repo directories to ingest: the minimal antichain of directories that
    hold a unit marker. Minimal because build_model walks a subtree, so once a
    directory is a unit, any marker-bearing directory below it is already
    covered; keeping only the topmost avoids re-ingesting the same files."""
    marked = sorted({p.parent for p in corpus.rglob("*")
                     if p.is_file() and p.name in _UNIT_MARKERS})
    units: list[Path] = []
    for d in marked:  # sorted: an ancestor always precedes its descendants
        if not any(d == u or u in d.parents for u in units):
            units.append(d)
    return units


def surfaces_for(unit: Path):
    """Text surfaces from one repo, fail-soft: a malformed config or unreadable
    file in a scraped corpus yields nothing rather than aborting the run."""
    try:
        return gather_surfaces(build_model(unit))
    except Exception:
        return []


def label_corpus(
    corpus: Path,
    eval_pct: int = 15,
    pos: float = POS_THRESHOLD,
    neg: float = NEG_THRESHOLD,
    max_neg_ratio: float | None = None,
    positive_paths: list[Path] | None = None,
) -> dict:
    """Weak-label a corpus end to end: gather + label + fold public positives +
    cap negatives + split. Returns {"train", "eval", "review", "stats"}.

    Order matters and is fixed here so callers cannot get it wrong: public
    positives are folded BEFORE the negative cap (so the cap balances against
    the true positive count) and BEFORE the split (so folded positives reach
    both train and eval, not just train). train/eval rows are the minimal
    {text, label} finetune.py consumes; review rows carry provenance for the
    human labeler.
    """
    seen: set[str] = set()
    rows: list[dict] = []
    review: list[dict] = []
    n_surfaces = 0

    for unit in iter_units(corpus):
        for s in surfaces_for(unit):
            n_surfaces += 1
            key = norm_key(s.text)
            if not key or key in seen:
                continue
            seen.add(key)
            prob, evidence = heuristic_score(s.text)
            lab = band(prob, pos, neg)
            if lab is None:
                review.append({
                    "text": s.text,
                    "score": round(prob, 4),
                    "categories": sorted({e.split(":", 1)[0] for e in evidence}),
                    "source": s.source,
                    "reason": "abstain",
                })
                continue
            rows.append({"text": s.text, "label": lab})

    n_corpus_pos = sum(r["label"] for r in rows)
    folded = merge_positives(rows, positive_paths or [], seen)
    if max_neg_ratio is not None:
        rows = _cap_negatives(rows, max_neg_ratio)

    train = [r for r in rows if split_of(norm_key(r["text"]), eval_pct) == "train"]
    eval_ = [r for r in rows if split_of(norm_key(r["text"]), eval_pct) == "eval"]

    stats = {
        "surfaces_seen": n_surfaces,
        "unique": len(seen),
        "corpus_positives": n_corpus_pos,
        "folded_positives": folded,
        "review": len(review),
        "train": len(train),
        "eval": len(eval_),
        "train_pos": sum(r["label"] for r in train),
        "eval_pos": sum(r["label"] for r in eval_),
    }
    return {"train": train, "eval": eval_, "review": review, "stats": stats}


def _cap_negatives(rows: list[dict], ratio: float) -> list[dict]:
    """Keep at most ratio negatives per positive, so a corpus that is almost
    all benign does not drown the signal. Deterministic: negatives are kept in
    corpus order, not sampled."""
    pos = [r for r in rows if r["label"] == 1]
    neg = [r for r in rows if r["label"] == 0]
    cap = int(len(pos) * ratio) if pos else len(neg)
    return pos + neg[:cap]


def merge_positives(rows: list[dict], paths: list[Path], seen: set[str]) -> int:
    """Fold labeled positive examples from external JSONL (public injection
    corpora, or the eval slices) into a row list, deduped against what is
    already there. Returns how many were added. The real-corpus negatives are
    the asset only we have; public positives round out a trainable balance."""
    added = 0
    for p in paths:
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if int(obj.get("label", 0)) != 1:
                continue
            key = norm_key(str(obj["text"]))
            if not key or key in seen:
                continue
            seen.add(key)
            rows.append({"text": str(obj["text"]), "label": 1})
            added += 1
    return added


def model_disagreements(review_texts: list[str], model: str, revision: str,
                        margin: float = 0.5) -> list[dict]:
    """Highest-value labels: where a trained model and the heuristic disagree
    by more than `margin`. Lazily loads the ML tier's classifier, so this path
    (and only this path) needs attestral[ml]/[onnx]."""
    from attestral.ml import MLConfig, _resolve_engine
    engine, _ = _resolve_engine(MLConfig(model=model, revision=revision, engine="auto"))
    out: list[dict] = []
    for text in review_texts:
        h_prob, _ = heuristic_score(text)
        m_prob, _ = engine(text)
        if abs(m_prob - h_prob) >= margin:
            out.append({
                "text": text,
                "heuristic": round(h_prob, 4),
                "model": round(m_prob, 4),
                "reason": "disagreement",
            })
    return out


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", required=True, help="Directory of MCP configs to label.")
    ap.add_argument("--out", default="data", help="Output directory for the JSONL files.")
    ap.add_argument("--eval-pct", type=int, default=15, help="Percent held out for eval.")
    ap.add_argument("--pos", type=float, default=POS_THRESHOLD, help="Positive score bar.")
    ap.add_argument("--neg", type=float, default=NEG_THRESHOLD, help="Negative score bar.")
    ap.add_argument("--max-neg-ratio", type=float, default=None,
                    help="Cap negatives at this multiple of positives per split.")
    ap.add_argument("--positives", nargs="*", default=[],
                    help="Extra positive-only JSONL to fold in (public corpora / eval slices).")
    ap.add_argument("--model", default=None,
                    help="Mine heuristic-vs-model disagreements with this model (needs attestral[ml]).")
    ap.add_argument("--revision", default="main", help="Model revision for --model.")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    result = label_corpus(Path(args.corpus), args.eval_pct, args.pos, args.neg,
                          args.max_neg_ratio,
                          positive_paths=[Path(p) for p in args.positives])
    train, eval_, review, stats = (result["train"], result["eval"],
                                   result["review"], result["stats"])

    if args.model:
        disagreements = model_disagreements([r["text"] for r in review], args.model,
                                            args.revision)
        review = review + disagreements
        stats["disagreements"] = len(disagreements)
        print(f"mined {len(disagreements)} heuristic-vs-model disagreements")

    _write_jsonl(out / "train.jsonl", train)
    _write_jsonl(out / "eval.jsonl", eval_)
    _write_jsonl(out / "review.jsonl", review)

    print("\nweak-supervision label generation complete")
    for k, v in stats.items():
        print(f"  {k:>16}: {v}")
    print(f"\n  wrote {out}/train.jsonl, {out}/eval.jsonl, {out}/review.jsonl")
    print("  next: python finetune.py --train {0}/train.jsonl --eval {0}/eval.jsonl "
          "--out ./attestral-injection-v1".format(out))


if __name__ == "__main__":
    main()
