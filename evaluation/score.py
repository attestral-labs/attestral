"""Score Attestral's agentic detection against the labelled benchmark.

Reports the three numbers the tool's credibility rests on:
  - recall on labelled positive cases (regression: every labelled finding fires),
  - false-positive rate on benign cases (the noise number that decides adoption),
  - rule coverage (which agentic rules have at least one positive case),
plus the known design-time gaps (rug-pull-class threats a static snapshot can't
see). Run `python -m evaluation.score` for the scorecard; it also writes
evaluation/RESULTS.md and evaluation/results.json. Deterministic, offline.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from attestral.ingest import build_model
from attestral.rules import RuleEngine

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
CASES = HERE / "cases.yaml"


def _is_agentic(rule_id: str) -> bool:
    """Agentic / cross-boundary rules live in the ATL-1xx and ATL-2xx bands."""
    return rule_id.startswith("ATL-1") or rule_id.startswith("ATL-2")


def _fired_agentic(path: str, engine: RuleEngine) -> set[str]:
    model = build_model(str(ROOT / path))
    return {f.rule_id for f in engine.evaluate(model) if _is_agentic(f.rule_id)}


def run() -> dict:
    """Evaluate every case and return the structured scorecard."""
    data = yaml.safe_load(CASES.read_text())
    engine = RuleEngine()
    all_agentic = {r["id"] for r in engine.rules if _is_agentic(r["id"])}

    positives = []
    tp_total = exp_total = 0
    for case in data.get("positive", []):
        expected = set(case["expect"])
        fired = _fired_agentic(case["path"], engine)
        tp = expected & fired
        missed = expected - fired          # a labelled finding that no longer fires
        extra = fired - expected           # fired but not labelled (review, not auto-FP)
        tp_total += len(tp)
        exp_total += len(expected)
        positives.append({
            "id": case["id"], "expected": sorted(expected), "fired": sorted(fired),
            "missed": sorted(missed), "extra": sorted(extra),
        })

    benign = []
    fp_total = 0
    for case in data.get("benign", []):
        fired = _fired_agentic(case["path"], engine)
        fp_total += len(fired)
        benign.append({"id": case["id"], "false_positives": sorted(fired)})

    gaps = [
        {"id": c["id"], "threat": c["threat"], "expect_class": c.get("expect_class", ""),
         "note": " ".join(c.get("note", "").split())}
        for c in data.get("gap", [])
    ]

    covered = set().union(*[set(c["expect"]) for c in data.get("positive", [])]) & all_agentic
    uncovered = sorted(all_agentic - covered)

    recall = (tp_total / exp_total) if exp_total else 0.0
    fp_rate = (sum(1 for b in benign if b["false_positives"]) / len(benign)) if benign else 0.0
    return {
        "recall": round(recall, 4),
        "labelled_findings": exp_total,
        "found": tp_total,
        "false_positive_findings": fp_total,
        "benign_fp_rate": round(fp_rate, 4),
        "coverage": round(len(covered) / len(all_agentic), 4) if all_agentic else 0.0,
        "agentic_rules": len(all_agentic),
        "rules_covered": len(covered),
        "uncovered_rules": uncovered,
        "positives": positives,
        "benign": benign,
        "gaps": gaps,
    }


def format_scorecard(r: dict) -> str:
    lines = [
        "Attestral agentic-detection benchmark",
        "=" * 44,
        f"  Recall (labelled findings that fire) : {r['found']}/{r['labelled_findings']}  "
        f"({r['recall'] * 100:.1f}%)",
        f"  False positives on benign designs    : {r['false_positive_findings']}  "
        f"(benign case FP-rate {r['benign_fp_rate'] * 100:.1f}%)",
        f"  Agentic-rule coverage                : {r['rules_covered']}/{r['agentic_rules']}  "
        f"({r['coverage'] * 100:.1f}%)",
    ]
    misses = [(p["id"], p["missed"]) for p in r["positives"] if p["missed"]]
    if misses:
        lines.append("  Regressions (labelled but not firing):")
        for cid, m in misses:
            lines.append(f"    - {cid}: {', '.join(m)}")
    extras = [(p["id"], p["extra"]) for p in r["positives"] if p["extra"]]
    if extras:
        lines.append("  Unlabelled fires (review, not counted as FP):")
        for cid, e in extras:
            lines.append(f"    - {cid}: {', '.join(e)}")
    if r["false_positive_findings"]:
        lines.append("  FALSE POSITIVES on benign designs:")
        for b in r["benign"]:
            if b["false_positives"]:
                lines.append(f"    - {b['id']}: {', '.join(b['false_positives'])}")
    if r["uncovered_rules"]:
        lines.append(f"  Uncovered agentic rules (no positive case): {', '.join(r['uncovered_rules'])}")
    if r["gaps"]:
        lines.append("  Known design-time gaps (runtime-only, by construction):")
        for g in r["gaps"]:
            lines.append(f"    - {g['id']}: {g['threat']}")
    return "\n".join(lines)


def format_markdown(r: dict) -> str:
    md = [
        "# Attestral agentic-detection benchmark - results",
        "",
        "Generated by `python -m evaluation.score`. Deterministic and offline. See",
        "`evaluation/README.md` for what each number means and how it is labelled.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Recall (labelled findings that fire) | {r['found']}/{r['labelled_findings']} "
        f"({r['recall'] * 100:.1f}%) |",
        f"| False positives on benign designs | {r['false_positive_findings']} "
        f"(FP-rate {r['benign_fp_rate'] * 100:.1f}%) |",
        f"| Agentic-rule coverage | {r['rules_covered']}/{r['agentic_rules']} "
        f"({r['coverage'] * 100:.1f}%) |",
        "",
        "## Positive cases (recall / regression)",
        "",
        "| Case | Found | Missed | Unlabelled fires |",
        "|---|---|---|---|",
    ]
    for p in r["positives"]:
        found = f"{len(set(p['expected']) & set(p['fired']))}/{len(p['expected'])}"
        md.append(f"| `{p['id']}` | {found} | {', '.join(p['missed']) or '-'} | "
                  f"{', '.join(p['extra']) or '-'} |")
    md += ["", "## Benign cases (false-positive rate)", "",
           "| Case | False positives |", "|---|---|"]
    for b in r["benign"]:
        md.append(f"| `{b['id']}` | {', '.join(b['false_positives']) or 'none'} |")
    if r["uncovered_rules"]:
        md += ["", "## Uncovered agentic rules", "",
               "No positive case exercises these yet (coverage debt):", "",
               "`" + "`, `".join(r["uncovered_rules"]) + "`"]
    md += ["", "## Known design-time gaps", "",
           "Threats a single design-time snapshot cannot see; detection is "
           "runtime-side (drift). Recorded, not hidden.", ""]
    for g in r["gaps"]:
        md.append(f"- **{g['id']}** - {g['threat']} {g['note']}")
    return "\n".join(md) + "\n"


def main() -> None:
    r = run()
    print(format_scorecard(r))
    (HERE / "RESULTS.md").write_text(format_markdown(r))
    (HERE / "results.json").write_text(json.dumps(r, indent=2) + "\n")


if __name__ == "__main__":
    main()
