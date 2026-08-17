#!/usr/bin/env python3
"""int8-dynamic-quantize an exported ONNX prompt-injection graph.

This exists to make the int8 measurement in evaluation/ml-efficiency.md
reproducible - it is a *research* tool, not a shipped tier. The measured result
is that naive int8 dynamic quantization COLLAPSES this DeBERTa-v3 detector's
recall (0.414 -> 0.133 on the labeled set; near-zero scores on blatant
injections), so attestral does not ship an int8 tier. Run this only to reproduce
that negative result, e.g. before trying calibration or quantization-aware
training that might recover it.

Usage:
    python scripts/export_onnx.py --out onnx-export          # fp32 graph first
    python scripts/quantize_onnx.py onnx-export onnx-int8     # then int8 it
    python -m evaluation.ml_eval --engine onnx --model onnx-int8 --label onnx-int8

The tokenizer + config are copied verbatim so the output dir loads standalone;
only model.onnx is quantized, per-tensor QInt8 weights (onnxruntime's default
dynamic path). Producing the fp32 graph needs optimum; quantizing needs only
onnxruntime.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path


def quantize(src: Path, dst: Path) -> int:
    try:
        from onnxruntime.quantization import QuantType, quantize_dynamic
    except ImportError:
        print("error: onnxruntime is required "
              '(pip install "attestral[onnx]")', file=sys.stderr)
        return 1
    model = src / "model.onnx"
    if not model.is_file():
        print(f"error: {model} not found - run scripts/export_onnx.py first",
              file=sys.stderr)
        return 1

    dst.mkdir(parents=True, exist_ok=True)
    # Tokenizer + config travel with the quantized graph so the dir loads
    # standalone (AutoTokenizer/AutoConfig + _resolve_onnx_weights).
    for f in src.iterdir():
        if f.is_file() and f.name != "model.onnx":
            shutil.copy2(f, dst / f.name)

    quantize_dynamic(str(model), str(dst / "model.onnx"), weight_type=QuantType.QInt8)
    fp32 = model.stat().st_size / 1e6
    int8 = (dst / "model.onnx").stat().st_size / 1e6
    print(f"quantized {fp32:.0f}MB -> {int8:.0f}MB int8 dynamic (QInt8 weights) -> {dst}")
    print("NOTE: measured to collapse recall on the injection task - "
          "see evaluation/ml-efficiency.md. Not a shippable tier.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("src", type=Path, help="fp32 ONNX export dir (from export_onnx.py)")
    ap.add_argument("dst", type=Path, help="output dir for the int8 graph + tokenizer")
    args = ap.parse_args()
    return quantize(args.src, args.dst)


if __name__ == "__main__":
    raise SystemExit(main())
