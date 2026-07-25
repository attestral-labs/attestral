"""Fine-tune a prompt-injection classifier for the Attestral ML layer.

Reads JSON Lines ({"text": ..., "label": 0|1}) and fine-tunes a DeBERTa-v3
sequence classifier. The output directory drops straight into
`attestral scan --ml --ml-model <dir>`.

    pip install -r requirements.txt
    python finetune.py --train data/train.jsonl --eval data/eval.jsonl --out ./model

This lives outside the `attestral` package on purpose: training pulls heavy
deps (transformers, torch, datasets) that the tool itself never imports.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def load_jsonl(path: str) -> list[dict]:
    rows = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = json.loads(line)
        rows.append({"text": str(obj["text"]), "label": int(obj["label"])})
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default="protectai/deberta-v3-base-prompt-injection-v2",
                    help="Base model to fine-tune from.")
    ap.add_argument("--train", required=True, help="Training JSONL.")
    ap.add_argument("--eval", required=True, help="Eval JSONL.")
    ap.add_argument("--out", default="./attestral-injection-v1", help="Output dir.")
    ap.add_argument("--epochs", type=float, default=3.0)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--max-length", type=int, default=512)
    args = ap.parse_args()

    import numpy as np
    from datasets import Dataset
    from transformers import (
        AutoModelForSequenceClassification,
        AutoTokenizer,
        DataCollatorWithPadding,
        Trainer,
        TrainingArguments,
    )

    tok = AutoTokenizer.from_pretrained(args.base)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base,
        num_labels=2,
        id2label={0: "SAFE", 1: "INJECTION"},
        label2id={"SAFE": 0, "INJECTION": 1},
        ignore_mismatched_sizes=True,
    )

    def tokenize(batch):
        return tok(batch["text"], truncation=True, max_length=args.max_length)

    train_ds = Dataset.from_list(load_jsonl(args.train)).map(tokenize, batched=True)
    eval_ds = Dataset.from_list(load_jsonl(args.eval)).map(tokenize, batched=True)

    def metrics(eval_pred):
        logits, labels = eval_pred
        preds = np.argmax(logits, axis=-1)
        tp = int(((preds == 1) & (labels == 1)).sum())
        fp = int(((preds == 1) & (labels == 0)).sum())
        fn = int(((preds == 0) & (labels == 1)).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {"precision": precision, "recall": recall, "f1": f1,
                "accuracy": float((preds == labels).mean())}

    targs = TrainingArguments(
        output_dir=args.out,
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        per_device_train_batch_size=args.batch,
        per_device_eval_batch_size=args.batch,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        logging_steps=25,
    )

    # transformers >= 5 renamed the Trainer's `tokenizer` argument to
    # `processing_class`; support both so this runs on either major version.
    trainer_kwargs = dict(
        model=model,
        args=targs,
        train_dataset=train_ds,
        eval_dataset=eval_ds,
        data_collator=DataCollatorWithPadding(tok),
        compute_metrics=metrics,
    )
    try:
        trainer = Trainer(**trainer_kwargs, processing_class=tok)
    except TypeError:
        trainer = Trainer(**trainer_kwargs, tokenizer=tok)
    trainer.train()
    print("eval:", trainer.evaluate())
    trainer.save_model(args.out)
    tok.save_pretrained(args.out)
    print(f"\nsaved to {args.out}\n"
          f"use it:  attestral scan ./my-agent --ml --ml-model {args.out}")


if __name__ == "__main__":
    main()
