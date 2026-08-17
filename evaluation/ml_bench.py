"""Measure the ML tiers' efficiency: cold-start, latency, throughput, footprint.

`evaluation/ml_eval.py` answers *how accurate* each tier is; this module
answers *what each tier costs*. Together they are the whole tier-selection
story: the heuristic is free but pattern-bound, the model tiers buy recall on
paraphrased/novel phrasing - this measures exactly what that buys costs in
startup time, per-surface latency, memory, and bytes on disk.

Method, chosen so the numbers describe what `attestral scan --ml` actually does:

- **Fresh subprocess per tier.** attestral.ml imports its heavy deps lazily
  inside the engine builders, so the first engine build pays the real
  import + model-load cost. Measuring every tier in one process would let the
  second tier ride the first one's warm imports and shared allocator; a
  subprocess makes cold-start genuinely cold and peak RSS attributable.
- **Production scoring path.** Latency is measured through the same
  `_chunks`-windowed max-prob scoring `ml.scan()` uses (via ml_eval.score_text),
  per surface, after a small warm-up so first-inference graph optimization is
  reported separately (as `first_score_s`) instead of polluting the median.
- **Latency corpus = the labeled eval set.** Real injection/benign surface
  lengths, not synthetic padding, so per-surface latency reflects the texts a
  scan actually scores.
- **Footprint is measured on disk.** Model bytes are the resolved artifact
  (ONNX graph file, or the HF snapshot minus the onnx/ export the torch tier
  never loads); memory is the process's peak RSS after scoring. Dependency bytes
  are the installed site-packages of each tier's *direct* imports - a floor, not
  a full closure (transitive deps like torch's sympy/networkx are not summed), so
  read deps_mb as "at least this much," and the RSS number as the real resident
  cost. Single-run numbers; re-run for an error bar (observed run-to-run spread
  is ~7-10% on latency and RSS).

    python -m evaluation.ml_bench                       # all installed tiers
    python -m evaluation.ml_bench --engine onnx         # one tier
    python -m evaluation.ml_bench --variant int8=/path  # extra onnx-dir variant

Writes `evaluation/ml-bench-results.json`. The published write-up joining
these numbers with ml_eval's accuracy numbers lives in
`evaluation/ml-efficiency.md`.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABELED = HERE / "data" / "deepset-prompt-injections.jsonl"
RESULTS = HERE / "ml-bench-results.json"

TIERS = ["heuristic", "onnx", "deberta"]

# site-packages roots each tier drags in, for the installed-footprint read.
# transformers appears in both model tiers (the tokenizer needs it); the
# heuristic is stdlib-only by design contract, so its list is empty.
_TIER_DEPS: dict[str, list[str]] = {
    "heuristic": [],
    "onnx": ["onnxruntime", "transformers", "numpy", "tokenizers"],
    "deberta": ["torch", "transformers", "numpy", "tokenizers"],
}

_WARMUP = 5


def _percentile(sorted_vals: list[float], p: float) -> float:
    """Nearest-rank percentile over an ascending list (no numpy dependency)."""
    if not sorted_vals:
        return 0.0
    k = max(0, min(len(sorted_vals) - 1, round(p / 100 * (len(sorted_vals) - 1))))
    return sorted_vals[k]


def _dir_bytes(path: Path, exclude_dirs: tuple[str, ...] = ()) -> int:
    return sum(
        f.stat().st_size for f in path.rglob("*")
        if f.is_file() and not any(d in f.parts for d in exclude_dirs)
    )


def _deps_bytes(names: list[str]) -> int:
    """Installed bytes of the named site-packages dirs (0 for a missing one)."""
    import importlib.util

    total = 0
    for name in names:
        spec = importlib.util.find_spec(name)
        if spec is None or not spec.origin:
            continue
        pkg_dir = Path(spec.origin).parent
        total += _dir_bytes(pkg_dir)
    return total


def _model_bytes(tier: str, cfg) -> int:
    """Bytes of the model artifact the tier actually loads."""
    if tier == "heuristic":
        return 0
    if tier == "onnx":
        from attestral.ml import _resolve_onnx_weights

        onnx_path = _resolve_onnx_weights(cfg)
        return Path(onnx_path).stat().st_size if onnx_path else 0
    # deberta/torch loads only the torch weight format (safetensors / .bin) plus
    # the tokenizer - NOT the onnx/ export that may also sit in the HF snapshot.
    # Excluding onnx/ is what keeps this from double-counting a second full copy
    # of the weights the torch tier never touches.
    p = Path(cfg.model)
    if p.is_dir():
        return _dir_bytes(p, exclude_dirs=("onnx",))
    try:
        from huggingface_hub import snapshot_download

        snap = snapshot_download(cfg.model, revision=cfg.revision, local_files_only=True)
        return _dir_bytes(Path(snap), exclude_dirs=("onnx",))
    except Exception:
        return 0


def _peak_rss_bytes() -> int:
    """Peak RSS of this process. ru_maxrss is bytes on macOS, KiB on Linux."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if platform.system() == "Darwin" else peak * 1024


def worker(tier: str, model: str | None, limit: int) -> dict:
    """Measure one tier in this (fresh) process; return the result dict."""
    from attestral.ml import MLConfig

    from evaluation.ml_eval import build_engine, load_jsonl, score_text

    cfg = MLConfig(**({"model": model} if model else {}))
    texts = [r["text"] for r in load_jsonl(LABELED)][: limit or None]

    t0 = time.perf_counter()
    engine = build_engine(tier, cfg)
    build_s = time.perf_counter() - t0
    if engine is None:
        return {"skipped": True, "reason": "dependencies or weights not installed"}

    t0 = time.perf_counter()
    score_text(engine, texts[0], cfg)
    first_score_s = time.perf_counter() - t0
    for t in texts[1:_WARMUP]:
        score_text(engine, t, cfg)

    lats: list[float] = []
    t_run = time.perf_counter()
    for t in texts:
        t0 = time.perf_counter()
        score_text(engine, t, cfg)
        lats.append(time.perf_counter() - t0)
    total_s = time.perf_counter() - t_run

    lats.sort()
    return {
        "n_texts": len(texts),
        "build_s": round(build_s, 4),
        "first_score_s": round(first_score_s, 4),
        "latency_ms": {
            "mean": round(sum(lats) / len(lats) * 1000, 3),
            "p50": round(_percentile(lats, 50) * 1000, 3),
            "p95": round(_percentile(lats, 95) * 1000, 3),
            "p99": round(_percentile(lats, 99) * 1000, 3),
        },
        "throughput_per_s": round(len(texts) / total_s, 1),
        "peak_rss_mb": round(_peak_rss_bytes() / 1e6, 1),
        "model_mb": round(_model_bytes(tier, cfg) / 1e6, 1),
        "deps_mb": round(_deps_bytes(_TIER_DEPS.get(tier, [])) / 1e6, 1),
    }


def run_tier(tier: str, model: str | None, limit: int) -> dict:
    """Run one tier's worker in a fresh subprocess and parse its JSON line."""
    cmd = [sys.executable, "-m", "evaluation.ml_bench", "--worker", "--engine", tier,
           "--limit", str(limit)]
    if model:
        cmd += ["--model", model]
    # Pin the model load to the local cache so a network etag round-trip never
    # leaks into build_s. (Page-cache warmth across runs is still a caveat - the
    # first-ever read of a 700MB weight file is disk-cold; report >=N runs for a
    # real error bar.)
    env = {**os.environ, "HF_HUB_OFFLINE": "1", "TOKENIZERS_PARALLELISM": "false"}
    proc = subprocess.run(
        cmd, capture_output=True, text=True, cwd=HERE.parent, timeout=1800, env=env,
    )
    if proc.returncode != 0:
        return {"skipped": True, "reason": f"worker failed: {proc.stderr.strip()[-300:]}"}
    # The worker prints exactly one JSON line last; model libs may log above it.
    return json.loads(proc.stdout.strip().splitlines()[-1])


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--engine", choices=TIERS, help="Bench a single tier (default: all).")
    ap.add_argument("--limit", type=int, default=0,
                    help="Cap the latency corpus at N texts (default: all rows).")
    ap.add_argument("--variant", action="append", default=[], metavar="NAME=DIR",
                    help="Extra onnx-tier variant from a local model dir "
                         "(e.g. int8=/path/to/quantized-export). Repeatable.")
    ap.add_argument("--model", help="(worker) model override for this tier.")
    ap.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.worker:
        print(json.dumps(worker(args.engine, args.model, args.limit)))
        return

    jobs: list[tuple[str, str, str | None]] = [
        (t, t, None) for t in ([args.engine] if args.engine else TIERS)
    ]
    for spec in args.variant:
        name, _, path = spec.partition("=")
        if not path:
            ap.error(f"--variant needs NAME=DIR, got {spec!r}")
        jobs.append((f"onnx-{name}", "onnx", path))

    out: dict = {
        "host": {"machine": platform.machine(), "system": platform.system(),
                 "python": platform.python_version()},
        "latency_corpus": LABELED.name,
        "tiers": {},
    }
    for label, tier, model in jobs:
        print(f"== {label} ...", flush=True)
        res = run_tier(tier, model, args.limit)
        out["tiers"][label] = res
        if res.get("skipped"):
            print(f"   SKIPPED: {res['reason']}")
            continue
        lat = res["latency_ms"]
        print(f"   build {res['build_s']:.2f}s  first-score {res['first_score_s']:.2f}s  "
              f"latency p50 {lat['p50']:.2f}ms p95 {lat['p95']:.2f}ms  "
              f"throughput {res['throughput_per_s']:.0f}/s")
        print(f"   peak RSS {res['peak_rss_mb']:.0f}MB  model {res['model_mb']:.0f}MB  "
              f"deps {res['deps_mb']:.0f}MB")

    RESULTS.write_text(json.dumps(out, indent=2) + "\n")
    print(f"\nwrote {RESULTS.relative_to(HERE.parent)}")


if __name__ == "__main__":
    main()
