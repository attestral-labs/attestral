"""Successor bake-off: is a newer detector a better default than the incumbent?

Our shipped default, `protectai/deberta-v3-base-prompt-injection-v2`, is archived
and unmaintained (the vendor was acquired). This scores a candidate successor
against it on the SAME slices `ml_eval` uses, through the SAME production chunk
scoring, so the comparison is apples-to-apples with what `attestral scan --ml`
actually does.

Candidate: `patronus-studio/wolf-defender-prompt-injection-small` (ModernBERT /
mmBERT-base, ~0.1B params, 8192-token context, Apache-2.0). It ships no
`id2label`; a probe confirms logit index 1 is the injection class (0.96 on
blatant injections, 0.04 on benign), which this hard-codes.

**Contamination caveat, load-bearing.** `deepset` is in-training for BOTH models
(it is on the protectai DeBERTa model card, and Wolf-Defender trained on "publicly
available prompt injection datasets" which very likely includes it), so the
`deepset` row is not a held-out read for either - it is reported for continuity
and excluded from the decision. The decision-grade rows are the self-authored
paraphrase / obfuscation / multilingual slices (written in this repo, so verbatim
in neither model's training) and the over-defense false-positive slice.

**Small samples - read the per-slice significance, not the blended mean.** These
slices are small (paraphrase 15/12, obfuscation 39/14, multilingual 15/7,
over-defense 48). An unweighted mean recall over them hides that most of the
gap comes from ONE slice; the write-up leads with the per-slice result and its
significance instead. All scoring is at the single shipped 0.5 threshold (no
per-model sweep), so the comparison is at DeBERTa's tuned operating point.

    python -m evaluation.successor_bakeoff

Writes `evaluation/successor-bakeoff.json`. Write-up joins these numbers with the
efficiency read in `ml-efficiency.md`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from attestral.ml import MLConfig, _resolve_engine

from evaluation.ml_eval import (
    LABELED,
    _labeled_slice,
    multilingual_slice,
    obfuscation_slice,
    over_defense_slice,
    paraphrase_slice,
)

HERE = Path(__file__).resolve().parent
RESULTS = HERE / "successor-bakeoff.json"

CANDIDATE = "patronus-studio/wolf-defender-prompt-injection-small"
# deepset is likely in the candidate's training mix (see module docstring), so it
# is reported but excluded from the decision.
CONTAMINATED_FOR_CANDIDATE = {"deepset"}


def _incumbent_engine(cfg: MLConfig):
    """The shipped default detector through the production resolver."""
    engine, notes = _resolve_engine(MLConfig(engine="deberta", threshold=cfg.threshold))
    if notes:
        raise RuntimeError(f"incumbent tier unavailable: {notes}")
    return engine


def _wolf_defender_engine():
    """Wolf-Defender as an ml-layer engine: (text) -> (injection_prob, []).

    The checkpoint's tokenizer_config names a backend class the installed
    transformers does not register, so the fast tokenizer is loaded straight from
    tokenizer.json. Index 1 is the injection class (probed). No pattern evidence,
    like every model tier.
    """
    import numpy as np
    import torch
    from huggingface_hub import snapshot_download
    from transformers import AutoModelForSequenceClassification, PreTrainedTokenizerFast

    p = snapshot_download(CANDIDATE)
    tok = PreTrainedTokenizerFast(
        tokenizer_file=os.path.join(p, "tokenizer.json"),
        pad_token="[PAD]", cls_token="[CLS]", sep_token="[SEP]", unk_token="[UNK]",
    )
    mdl = AutoModelForSequenceClassification.from_pretrained(p).eval()

    def engine(text: str):
        enc = tok(text, truncation=True, max_length=512, return_tensors="pt")
        with torch.no_grad():
            logits = mdl(**enc).logits[0].numpy()
        exp = np.exp(logits - logits.max())
        return float((exp / exp.sum())[1]), []

    return engine


def _efficiency(engine, texts: list[str]) -> dict:
    """p50/p95 latency over the labeled corpus through the same per-surface
    scoring, after a short warm-up. Measured here so the cost numbers are
    reproducible from this harness, not quoted from elsewhere."""
    import time

    from evaluation.ml_eval import score_text

    cfg = MLConfig()
    for t in texts[:5]:
        score_text(engine, t, cfg)
    lat = []
    for t in texts:
        a = time.perf_counter()
        score_text(engine, t, cfg)
        lat.append(time.perf_counter() - a)
    lat.sort()
    return {"p50_ms": round(lat[len(lat) // 2] * 1000, 1),
            "p95_ms": round(lat[int(len(lat) * 0.95)] * 1000, 1),
            "throughput_per_s": round(len(lat) / sum(lat), 1)}


def _model_mb(model_id: str | None) -> float:
    """Bytes of the torch weight file the model loads (0 if not local)."""
    if not model_id:
        return 0.0
    try:
        from huggingface_hub import snapshot_download
        snap = Path(snapshot_download(model_id, local_files_only=True))
        sf = snap / "model.safetensors"
        return round(sf.stat().st_size / 1e6, 1) if sf.is_file() else 0.0
    except Exception:
        return 0.0


def _slice_metrics(name: str, engine, cfg: MLConfig) -> dict:
    if name == "deepset":
        s = _labeled_slice(engine, cfg, LABELED)
    elif name == "paraphrase":
        s = paraphrase_slice(engine, cfg)
    elif name == "obfuscation":
        s = obfuscation_slice(engine, cfg)
    elif name == "multilingual":
        s = multilingual_slice(engine, cfg)
    else:  # over_defense - benign-only, recall undefined
        od = over_defense_slice(engine, cfg)
        return {"recall": None, "fp_rate": od["fp_rate"],
                "n_pos": 0, "n_neg": od["n"]}
    return {"recall": s["recall"], "fp_rate": s["fp_rate"],
            "n_pos": s["n_pos"], "n_neg": s["n_neg"]}


SLICES = ("deepset", "paraphrase", "obfuscation", "multilingual", "over_defense")


def run() -> dict:
    cfg = MLConfig()
    from evaluation.ml_eval import load_jsonl
    texts = [r["text"] for r in load_jsonl(LABELED)]
    models = {
        "incumbent-deberta-v2": (_incumbent_engine(cfg), None),
        "wolf-defender-small": (_wolf_defender_engine(), CANDIDATE),
    }
    out: dict = {"threshold": cfg.threshold, "candidate": CANDIDATE, "models": {}}
    for label, (engine, model_id) in models.items():
        rows = {name: _slice_metrics(name, engine, cfg) for name in SLICES}
        rows["_efficiency"] = {**_efficiency(engine, texts), "model_mb": _model_mb(model_id)}
        out["models"][label] = rows
        print(f"\n== {label}")
        for name in SLICES:
            m = rows[name]
            rec = "  n/a" if m["recall"] is None else f"{m['recall']:.3f}"
            tag = "  [contaminated for candidate]" if name in CONTAMINATED_FOR_CANDIDATE else ""
            print(f"   {name:13} recall {rec}  fp_rate {m['fp_rate']:.3f}"
                  f"  (n+ {m['n_pos']} / n- {m['n_neg']}){tag}")
        eff = rows["_efficiency"]
        print(f"   efficiency    p50 {eff['p50_ms']}ms  {eff['throughput_per_s']}/s  "
              f"model {eff['model_mb']}MB")

    # Decision view: mean recall on the UNCONTAMINATED positive slices + the
    # over-defense false-positive rate. This is the fair comparison.
    print("\n== decision view (uncontaminated slices only)")
    for label, rows in out["models"].items():
        pos = [rows[s]["recall"] for s in SLICES
               if s not in CONTAMINATED_FOR_CANDIDATE and rows[s]["recall"] is not None]
        mean_rec = sum(pos) / len(pos) if pos else 0.0
        od = rows["over_defense"]["fp_rate"]
        out["models"][label]["_decision"] = {
            "mean_recall_uncontaminated": round(mean_rec, 4), "over_defense_fp_rate": od}
        print(f"   {label:22} mean recall (para+obf+multi) {mean_rec:.3f}"
              f"   over-defense FP {od:.3f}")

    RESULTS.write_text(json.dumps(out, indent=2) + "\n")
    print(f"\nwrote {RESULTS.relative_to(HERE.parent)}")
    return out


if __name__ == "__main__":
    run()
