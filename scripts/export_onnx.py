#!/usr/bin/env python3
"""Export the prompt-injection DeBERTa model to ONNX for the light `onnx` tier.

attestral's ML layer (attestral/ml.py) can score agentic text surfaces with the
same DeBERTa prompt-injection classifier through onnxruntime instead of torch -
model-grade accuracy at a ~30-50MB install. That path (``ORTModelForSequence-
Classification.from_pretrained``) needs ONNX weights to exist in the model repo
or the local HF cache. This maintenance script produces them.

It downloads the torch checkpoint once, converts it to ONNX via optimum, and
writes the ONNX model + tokenizer to an output directory you can then upload to
the model repo (or point ``ATTESTRAL_ML_MODEL`` at). Exporting needs torch +
optimum installed once; *running* the exported model needs only onnxruntime.

Usage:
    python scripts/export_onnx.py [--model ID] [--revision REV] [--out DIR]

Examples:
    # Export the pinned default model to ./onnx-export
    python scripts/export_onnx.py

    # Export a specific model/revision to a chosen directory
    python scripts/export_onnx.py --model protectai/deberta-v3-base-prompt-injection-v2 \
        --revision main --out /tmp/pi-onnx

The script degrades with a clear, actionable message (and a non-zero exit) when
optimum isn't installed or when the model/network is unavailable - it never
raises a raw traceback at the operator.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Keep this in sync with attestral.ml._DEFAULT_MODEL / _DEFAULT_REVISION.
DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
DEFAULT_REVISION = "main"


def _die(msg: str, code: int = 1) -> "int":
    print(f"error: {msg}", file=sys.stderr)
    return code


def export(model: str, revision: str, out: Path) -> int:
    """Export `model`@`revision` to ONNX under `out`. Returns a process exit code."""
    try:
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer
    except ImportError:
        return _die(
            "optimum + transformers are required to export.\n"
            '  Install the export toolchain with:  pip install "optimum[onnxruntime]"\n'
            "  (exporting also needs torch once; running the result needs only onnxruntime.)"
        )

    out.mkdir(parents=True, exist_ok=True)
    print(f"Exporting {model}@{revision} to ONNX -> {out}", file=sys.stderr)
    try:
        # export=True converts the torch checkpoint to ONNX on the fly.
        ort_model = ORTModelForSequenceClassification.from_pretrained(
            model, revision=revision, export=True
        )
        tokenizer = AutoTokenizer.from_pretrained(model, revision=revision)
    except Exception as exc:  # network down, unknown model, gated repo, ...
        return _die(
            f"could not download/convert {model!r} (revision {revision!r}): {exc}\n"
            "  Check the model id, that you have network access, and that any\n"
            "  license/gated-repo acceptance is done (huggingface-cli login)."
        )

    try:
        ort_model.save_pretrained(out)
        tokenizer.save_pretrained(out)
    except OSError as exc:
        return _die(f"could not write export to {out}: {exc}")

    files = sorted(p.name for p in out.glob("*.onnx"))
    print(
        f"Done. Wrote ONNX weights ({', '.join(files) or 'none found'}) + tokenizer to {out}.\n"
        f"  Point attestral at it with:  ATTESTRAL_ML_MODEL={out} attestral scan --ml PATH\n"
        f"  or upload the directory contents to the {model} repo so the `onnx` tier\n"
        f"  can load it by name.",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export the prompt-injection DeBERTa model to ONNX for attestral's light `onnx` tier.",
    )
    parser.add_argument("--model", default=DEFAULT_MODEL, help="HF model id to export.")
    parser.add_argument("--revision", default=DEFAULT_REVISION, help="Model revision / commit sha.")
    parser.add_argument(
        "--out", default="onnx-export", type=Path, help="Output directory for the ONNX model + tokenizer."
    )
    args = parser.parse_args(argv)
    return export(args.model, args.revision, args.out)


if __name__ == "__main__":
    raise SystemExit(main())
